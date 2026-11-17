//! `snitch --watch-ebpf`: file monitoring with BPF LSM programs (monitor
//! mode).
//!
//! The programs in `snitch-ebpf` run on the LSM hooks for writes,
//! truncation, unlink, rename, hard links, creation, chmod and chown. They
//! report operations on the files in the hash database and on entries of the
//! configured directories, identified by (device, inode). This module fills
//! their watch map and turns their events into messages. A file that was
//! opened for writing is hashed again when the writer closes it, and
//! reported if the hash differs from the database. Deleted inodes leave the
//! watch map when the kernel frees them, before their number can be reused.
//!
//! Two ways to get the programs:
//! - Pinned (meta-snitch): `snitch-ebpf-load` attached them from the
//!   initramfs, with self-protection, and pinned their maps. The daemon claims
//!   the maps; from then on nobody else can open them. It stores the map fds
//!   in systemd's fd store and gets them back from there after a restart.
//!   Refused tamper attempts are reported.
//! - Fallback (no pins): load and attach the monitoring programs here. They
//!   stay attached while this process runs.
//!
//! At every start, a background task hashes all files from the database and
//! reports the ones that changed or disappeared while snitch wasn't watching
//! (powered off, stopped, or before the first boot of an image whose
//! database was built with it).

mod selftest;

use std::collections::{HashMap as StdHashMap, HashSet};
use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use aya::maps::{Array, HashMap, Map, MapData, PerCpuArray, RingBuf};
use aya::Ebpf;
use eyre::{bail, ContextCompat, Result, WrapErr};
use snitch_ebpf_common::{
    Event, InodeKey, ABI_VERSION, CTL_ABI, CTL_DAEMON_TGID, CTL_LOCKED, EV_CHMOD, EV_CHOWN,
    EV_CLOSE_WRITE, EV_CREATE, EV_INODE_FREED, EV_LINK, EV_OPEN_WRITE, EV_RENAME_FROM,
    EV_RENAME_OVER, EV_TAMPER, EV_TRUNCATE, EV_UNLINK, STAT_DROPPED, STAT_READ_ERRORS,
    TAMPER_BPF_CMD, TAMPER_EXEC, TAMPER_EXEC_MMAP, TAMPER_EXE_WRITE, TAMPER_KILL, TAMPER_MAP_FD,
    TAMPER_MOVE_MOUNT, TAMPER_PIN_RENAME, TAMPER_PIN_UNLINK, TAMPER_PIVOT_ROOT, TAMPER_PTRACE,
    TAMPER_SYSCTL, TAMPER_UMOUNT, WATCH_DIR, WATCH_FILE,
};
use snitch_ebpf_loader::{inode_key, LoadOptions, DAEMON_MAPS, PIN_DIR};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use walkdir::WalkDir;

use crate::config::Config;
use crate::dispatcher::{MessageBackend, SnitchDispatcher};
use crate::hashing::{hash_file, hash_file_sync};
use crate::heartbeat::{self, Mode, SharedHealth};
use crate::persist::open_database;

/// Hash a file again this long after it was opened for writing, in case the
/// writer keeps it open.
const OPEN_WRITE_RECHECK: Duration = Duration::from_secs(5);
/// LSM hooks run before the operation; look at the result this much later.
const AFTER_OPERATION: Duration = Duration::from_secs(1);
const STATS_INTERVAL: Duration = Duration::from_secs(30);
/// Report a repeated tamper attempt (same kind, detail and process name) at
/// most this often.
const TAMPER_REPEAT: Duration = Duration::from_secs(60);
/// Names of the map fds in systemd's fd store: prefix + map name.
const FDNAME_PREFIX: &str = "snitch-map-";

/// Why `--watch` can't use BPF LSM programs here, or None if it can.
pub fn unavailable() -> Option<String> {
    if Path::new(PIN_DIR).join("map_CONTROL").exists() {
        return None;
    }
    if !Path::new("/sys/kernel/btf/vmlinux").exists() {
        return Some("the kernel has no BTF (CONFIG_DEBUG_INFO_BTF)".into());
    }
    match snitch_ebpf_loader::missing_lsm_hooks(false) {
        Ok(missing) if !missing.is_empty() => {
            return Some(format!(
                "the kernel lacks LSM hooks snitch needs: {}",
                missing.join(", ")
            ))
        }
        Err(err) => return Some(format!("{err:#}")),
        Ok(_) => {}
    }
    check_bpf_lsm_active().err().map(|err| err.to_string())
}

fn check_bpf_lsm_active() -> Result<()> {
    // securityfs may not be mounted; then attaching tells us.
    if let Ok(lsms) = std::fs::read_to_string("/sys/kernel/security/lsm") {
        if !lsms.trim().split(',').any(|l| l == "bpf") {
            bail!(
                "the BPF LSM is not active (active: {}). Add \"bpf\" to CONFIG_LSM or to the \
                 lsm= kernel parameter.",
                lsms.trim()
            );
        }
    }
    Ok(())
}

/// Path and hash of every file in the hash database.
fn read_baseline(config: &Config) -> Result<StdHashMap<PathBuf, String>> {
    let db = open_database(&config.database_path())?;
    let mut files = StdHashMap::new();
    for item in db.iter() {
        let (path, hash) = item?;
        files.insert(
            PathBuf::from(std::str::from_utf8(&path)?),
            std::str::from_utf8(&hash)?.to_owned(),
        );
    }
    Ok(files)
}

struct Watch {
    path: PathBuf,
    kind: u32,
}

enum Later {
    /// Hash the file and compare with the database.
    Hash { path: PathBuf, who: String },
    /// The path may point to another inode now: update the watch map.
    Resync(PathBuf),
    /// The startup check found the file missing.
    Missing(PathBuf),
}

/// Who changed a file that the startup check found changed.
const NOT_WATCHING: &str = "while snitch wasn't watching";

/// Hash every file from the database in a blocking thread; send the ones
/// that differ (hashed again and reported by the monitor) or are gone.
fn check_baseline(baseline: Vec<(PathBuf, String)>, later: mpsc::UnboundedSender<Later>) {
    tokio::task::spawn_blocking(move || {
        let start = Instant::now();
        let (mut changed, mut missing) = (0, 0);
        let total = baseline.len();
        for (path, expected) in baseline {
            match hash_file_sync(&path) {
                Ok(hash) if hash == expected => {}
                Ok(_) => {
                    changed += 1;
                    let who = NOT_WATCHING.to_string();
                    let _ = later.send(Later::Hash { path, who });
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    missing += 1;
                    let _ = later.send(Later::Missing(path));
                }
                Err(err) => debug!("startup check: {}: {err}", path.display()),
            }
        }
        info!(
            "startup check: {total} files hashed in {:.1} s, {changed} changed, {missing} missing",
            start.elapsed().as_secs_f64()
        );
    });
}

struct Monitor<'a> {
    dispatcher: &'a SnitchDispatcher,
    map: HashMap<MapData, InodeKey, u32>,
    by_key: StdHashMap<InodeKey, Watch>,
    by_path: StdHashMap<PathBuf, InodeKey>,
    baseline: StdHashMap<PathBuf, String>,
    /// Last mismatching hash reported per file, to report each change once.
    reported: StdHashMap<PathBuf, String>,
    /// Files reported removed (an unlink while snitch was stopped is also
    /// found missing by the startup check).
    removed: HashSet<PathBuf>,
    /// When each kind of tamper attempt was last reported.
    tamper_reported: StdHashMap<(u64, u64, String), Instant>,
    later: mpsc::UnboundedSender<Later>,
    selftest: selftest::SelfTest,
    /// Reported in heartbeats.
    health: SharedHealth,
}

/// The maps the daemon works with.
struct Maps {
    watched: MapData,
    events: MapData,
    stats: MapData,
    /// Fallback mode: keeps the programs attached.
    _bpf: Option<Ebpf>,
}

/// Fallback: load and attach the monitoring programs in this process.
fn load_here(n_watch: usize) -> Result<Maps> {
    // Room for files that get a new inode while we run.
    let max_watched = (n_watch + n_watch / 4 + 1024) as u32;
    let mut bpf = snitch_ebpf_loader::load(&LoadOptions {
        max_watched,
        protect: None,
    })?;
    snitch_ebpf_loader::attach_monitor(&mut bpf)?;
    let mut take = |name: &str| -> Result<MapData> {
        match bpf
            .take_map(name)
            .wrap_err_with(|| format!("map {name} missing"))?
        {
            Map::HashMap(m) | Map::RingBuf(m) | Map::PerCpuArray(m) => Ok(m),
            _ => bail!("map {name} has an unexpected type"),
        }
    };
    let watched = take("WATCHED")?;
    let events = take("EVENTS")?;
    let stats = take("STATS")?;
    Ok(Maps {
        watched,
        events,
        stats,
        _bpf: Some(bpf),
    })
}

/// Pinned: claim the maps the boot loader pinned. After a restart they come
/// from systemd's fd store (nobody can open the pins any more).
fn claim_pinned() -> Result<Maps> {
    let mut maps: StdHashMap<String, MapData> = StdHashMap::new();
    if let Ok(fds) = sd_notify::listen_fds_with_names() {
        for (fd, name) in fds {
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            if let Some(map) = name.strip_prefix(FDNAME_PREFIX) {
                maps.insert(map.to_owned(), MapData::from_fd(fd)?);
            }
        }
    }
    let from_store = !maps.is_empty();
    for name in DAEMON_MAPS {
        if maps.contains_key(*name) {
            continue;
        }
        let pin = Path::new(PIN_DIR).join(format!("map_{name}"));
        let map = MapData::from_pin(&pin).wrap_err_with(|| {
            format!(
                "opening {}. If this is \"Operation not permitted\", another process \
                 claimed snitch's maps first.",
                pin.display()
            )
        })?;
        maps.insert(name.to_string(), map);
    }
    if from_store {
        info!("BPF maps from systemd's fd store");
    } else if std::env::var_os("NOTIFY_SOCKET").is_some() {
        for (name, map) in &maps {
            let fdname = format!("{FDNAME_PREFIX}{name}");
            // FDPOLL=0: systemd drops stored fds that poll with EPOLLERR,
            // which BPF maps other than ring buffers always do.
            sd_notify::notify_with_fds(
                &[
                    sd_notify::NotifyState::FdStore,
                    sd_notify::NotifyState::FdName(&fdname),
                    sd_notify::NotifyState::Custom("FDPOLL=0"),
                ],
                &[map.fd().as_fd()],
            )
            .wrap_err("storing map fds with systemd (FileDescriptorStoreMax)")?;
        }
    } else {
        warn!(
            "not started by systemd: snitch's BPF maps can't be opened again after this \
             process exits (until reboot)"
        );
    }

    let mut control: Array<MapData, u32> =
        Array::try_from(Map::Array(maps.remove("CONTROL").unwrap()))?;
    let abi = control.get(&CTL_ABI, 0)?;
    if abi != ABI_VERSION {
        bail!(
            "the BPF programs loaded at boot are ABI version {abi}, this snitch needs \
             {ABI_VERSION}. Kernel image (initramfs) and root file system don't match."
        );
    }
    // From now on nobody else gets an fd for snitch's maps, and this process
    // is protected from signals and ptrace.
    control.set(CTL_LOCKED, 1, 0)?;
    control.set(CTL_DAEMON_TGID, std::process::id(), 0)?;

    Ok(Maps {
        watched: maps.remove("WATCHED").unwrap(),
        events: maps.remove("EVENTS").unwrap(),
        stats: maps.remove("STATS").unwrap(),
        _bpf: None,
    })
}

pub async fn watch_ebpf(config: &Config, dispatcher: &SnitchDispatcher) -> Result<()> {
    if std::mem::size_of::<usize>() != 8 {
        bail!("--watch-ebpf supports 64-bit systems only");
    }
    check_bpf_lsm_active()?;

    let baseline = read_baseline(config)?;
    if baseline.is_empty() {
        bail!("the hash database is empty; run snitch --init first");
    }

    let mut by_key = StdHashMap::new();
    let mut by_path = StdHashMap::new();
    for path in baseline.keys() {
        match std::fs::symlink_metadata(path) {
            Ok(md) if md.file_type().is_file() => {
                let key = inode_key(&md);
                by_key.entry(key).or_insert(Watch {
                    path: path.clone(),
                    kind: WATCH_FILE,
                });
                by_path.insert(path.clone(), key);
            }
            Ok(_) => {}
            Err(err) => warn!("{}: {err}. Not watched.", path.display()),
        }
    }
    let n_files = by_key.len();
    let db_path = config.database_path();
    for dir in config.directories() {
        let walker = WalkDir::new(dir)
            .into_iter()
            .filter_entry(|e| !e.path().starts_with(&db_path));
        for entry in walker.flatten() {
            if !entry.file_type().is_dir() {
                continue;
            }
            if let Ok(md) = entry.metadata() {
                by_key.entry(inode_key(&md)).or_insert(Watch {
                    path: entry.path().to_owned(),
                    kind: WATCH_DIR,
                });
            }
        }
    }
    let n_dirs = by_key.len() - n_files;

    let pinned = Path::new(PIN_DIR).join("map_CONTROL").exists();
    let maps = if pinned {
        claim_pinned()?
    } else {
        load_here(by_key.len())?
    };
    let capacity = maps.watched.info()?.max_entries() as usize;
    let mut map: HashMap<MapData, InodeKey, u32> = HashMap::try_from(Map::HashMap(maps.watched))?;
    // After a restart the map still holds the previous run's entries.
    let stale: Vec<InodeKey> = map
        .keys()
        .filter_map(|k| k.ok())
        .filter(|k| !by_key.contains_key(k))
        .collect();
    for key in &stale {
        let _ = map.remove(key);
    }
    let mut not_watched = 0;
    for (key, watch) in &by_key {
        if map.insert(key, watch.kind, 0).is_err() {
            not_watched += 1;
        }
    }
    if not_watched > 0 {
        warn!(
            "the BPF watch map is full ({capacity} entries): {not_watched} files and \
             directories are not watched. Raise snitch-ebpf-load --max-watched."
        );
    }
    info!(
        "watching {n_files} files and {n_dirs} directories with BPF LSM programs ({})",
        if pinned {
            "loaded at boot"
        } else {
            "loaded by this process"
        }
    );

    let mut events = AsyncFd::new(RingBuf::try_from(Map::RingBuf(maps.events))?)?;
    let stats: PerCpuArray<MapData, u64> = PerCpuArray::try_from(Map::PerCpuArray(maps.stats))?;
    let _keep_attached = maps._bpf;
    let (later_tx, mut later_rx) = mpsc::unbounded_channel();
    let selftest = selftest::SelfTest::new(pinned);
    info!(
        "self-test every {} s: {}",
        selftest::INTERVAL.as_secs(),
        selftest.scope()
    );
    let mode = if pinned {
        Mode::Protected
    } else {
        Mode::Unprotected
    };
    check_baseline(
        baseline
            .iter()
            .map(|(p, h)| (p.clone(), h.clone()))
            .collect(),
        later_tx.clone(),
    );
    let mut monitor = Monitor {
        dispatcher,
        map,
        by_key,
        by_path,
        baseline,
        reported: StdHashMap::new(),
        removed: HashSet::new(),
        tamper_reported: StdHashMap::new(),
        later: later_tx,
        selftest,
        health: heartbeat::start(config, mode),
    };
    monitor.health.lock().unwrap().watched = Some(n_files as u64);
    if std::env::var_os("NOTIFY_SOCKET").is_some() {
        let _ = sd_notify::notify(&[sd_notify::NotifyState::Ready]);
    }

    let mut stats_tick = tokio::time::interval(STATS_INTERVAL);
    let mut selftest_tick = tokio::time::interval(selftest::INTERVAL);
    // After a pause (SIGSTOP, suspend), no back-to-back rounds: the first
    // would be judged before its events arrive.
    selftest_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut dropped_reported = 0;
    let mut read_errors_logged = false;
    loop {
        tokio::select! {
            guard = events.readable_mut() => {
                let mut guard = guard?;
                let mut batch = Vec::new();
                while let Some(item) = guard.get_inner_mut().next() {
                    if item.len() < std::mem::size_of::<Event>() {
                        warn!("short BPF event ({} bytes)", item.len());
                        continue;
                    }
                    batch.push(unsafe { std::ptr::read_unaligned(item.as_ptr() as *const Event) });
                }
                guard.clear_ready();
                for event in batch {
                    monitor.handle(&event).await;
                }
            }
            Some(later) = later_rx.recv() => monitor.handle_later(later).await,
            _ = selftest_tick.tick() => {
                let dropped = stat_total(&stats, STAT_DROPPED)?;
                if let Some(verdict) = monitor.selftest.start(&mut monitor.map, dropped) {
                    monitor.verdict(verdict).await;
                }
            }
            _ = stats_tick.tick() => {
                let dropped = stat_total(&stats, STAT_DROPPED)?;
                monitor.health.lock().unwrap().events_dropped = dropped;
                if dropped > dropped_reported {
                    monitor
                        .send(
                            "eBPF events lost",
                            format!(
                                "{} file events were dropped (ring buffer full). Changes may have gone unnoticed; run snitch --scan.",
                                dropped - dropped_reported
                            ),
                        )
                        .await;
                    dropped_reported = dropped;
                }
                let read_errors = stat_total(&stats, STAT_READ_ERRORS)?;
                if read_errors > 0 && !read_errors_logged {
                    warn!("BPF programs failed {read_errors} kernel memory reads; some events may be missing");
                    read_errors_logged = true;
                }
            }
        }
    }
}

/// What a refused tamper attempt (`EV_TAMPER`) tried to do.
fn tamper_description(what: u64, detail: u64, name: &str) -> String {
    let fs = |magic: u64| match magic {
        0xcafe_4a11 => "snitch's bpffs",
        0x6265_6572 => "sysfs",
        _ => "the root file system",
    };
    match what {
        TAMPER_SYSCTL => {
            "write to kernel.ftrace_enabled (would disarm all BPF LSM programs)".into()
        }
        TAMPER_BPF_CMD => format!(
            "bpf() {} (would detach or replace a BPF program)",
            match detail {
                29 => "BPF_LINK_UPDATE",
                34 => "BPF_LINK_DETACH",
                _ => "command",
            }
        ),
        TAMPER_MAP_FD => format!("opening one of snitch's BPF maps (id {detail})"),
        TAMPER_PIN_UNLINK => format!("removing {PIN_DIR}/{name}"),
        TAMPER_PIN_RENAME => format!("renaming {PIN_DIR}/{name}"),
        TAMPER_UMOUNT => format!(
            "unmounting {} (would release snitch's BPF programs)",
            fs(detail)
        ),
        TAMPER_MOVE_MOUNT => "moving a mount (could release snitch's BPF programs)".into(),
        TAMPER_PIVOT_ROOT => "pivot_root".into(),
        TAMPER_KILL => format!("signal {detail} to snitch"),
        TAMPER_PTRACE => format!(
            "ptrace access to {}",
            if detail == 1 {
                "init (holds snitch's map fds)".to_string()
            } else {
                format!("snitch (pid {detail})")
            }
        ),
        TAMPER_EXEC => format!(
            "running {name} in snitch.service (would get snitch's BPF map fds; a unit drop-in?)"
        ),
        TAMPER_EXE_WRITE => format!(
            "{} {name}, which snitch.service may run",
            if detail == 1 {
                "truncating"
            } else {
                "opening for writing"
            }
        ),
        TAMPER_EXEC_MMAP => format!(
            "loading {name} as code into snitch.service: it isn't in the hash database \
             (LD_PRELOAD or the like?)"
        ),
        _ => format!("unknown kind {what}"),
    }
}

fn stat_total(stats: &PerCpuArray<MapData, u64>, idx: u32) -> Result<u64> {
    Ok(stats.get(&idx, 0)?.iter().sum())
}

fn c_str(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

impl Monitor<'_> {
    async fn send(&self, title: &str, body: String) {
        info!("{title}: {body}");
        let message = MessageBackend::new_now(title.to_string(), body);
        if let Err(err) = self.dispatcher.dispatch(message).await {
            error!("failed to dispatch message: {err:?}");
        }
    }

    fn after(&self, delay: Duration, later: Later) {
        let tx = self.later.clone();
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let _ = tx.send(later);
        });
    }

    async fn handle(&mut self, ev: &Event) {
        if self.selftest.owns(ev) {
            if let Some(verdict) = self.selftest.record(ev) {
                self.verdict(verdict).await;
            }
            return;
        }
        if ev.kind == EV_TAMPER {
            self.tamper(ev).await;
            return;
        }
        let key = InodeKey {
            dev: ev.dev,
            ino: ev.ino,
        };
        let Some(watch) = self.by_key.get(&key) else {
            // Removed from our index while the event was queued.
            debug!("event {} for unknown inode {key:?}", ev.kind);
            return;
        };
        let path = watch.path.clone();
        let name = c_str(&ev.name);
        let who = format!("by {} (pid {}, uid {})", c_str(&ev.comm), ev.tgid, ev.uid);

        match ev.kind {
            EV_OPEN_WRITE => {
                info!("{} opened for writing {who}", path.display());
                self.after(OPEN_WRITE_RECHECK, Later::Hash { path, who });
            }
            EV_CLOSE_WRITE => self.check_hash(&path, &who).await,
            EV_TRUNCATE => self.after(AFTER_OPERATION, Later::Hash { path, who }),
            EV_UNLINK => {
                self.removed.insert(path.clone());
                self.send("File removed", format!("{}\n{who}", path.display()))
                    .await;
                self.after(AFTER_OPERATION, Later::Resync(path));
            }
            EV_RENAME_FROM => {
                self.send(
                    "File renamed",
                    format!("{} renamed to \"{name}\"\n{who}", path.display()),
                )
                .await;
                self.after(AFTER_OPERATION, Later::Resync(path));
            }
            EV_RENAME_OVER => {
                self.send(
                    "File replaced",
                    format!("{} replaced by \"{name}\" (rename)\n{who}", path.display()),
                )
                .await;
                self.after(AFTER_OPERATION, Later::Resync(path.clone()));
                self.after(AFTER_OPERATION, Later::Hash { path, who });
            }
            EV_LINK => {
                self.send(
                    "Hard link created",
                    format!("\"{name}\" now links to {}\n{who}", path.display()),
                )
                .await;
            }
            EV_CREATE => {
                self.send(
                    "File created",
                    format!("{}\n{who}", path.join(&name).display()),
                )
                .await;
            }
            EV_CHMOD => {
                self.send("Permissions changed", format!("{}\n{who}", path.display()))
                    .await;
            }
            EV_CHOWN => {
                self.send("Owner changed", format!("{}\n{who}", path.display()))
                    .await;
            }
            EV_INODE_FREED => {
                // Already out of the watch map (the programs removed it).
                debug!("{}: inode {key:?} freed", path.display());
                self.by_key.remove(&key);
                if self.by_path.get(&path) == Some(&key) {
                    self.by_path.remove(&path);
                }
            }
            other => warn!("unknown BPF event kind {other}"),
        }
    }

    async fn verdict(&mut self, verdict: selftest::Verdict) {
        let (ok, detail) = match verdict {
            selftest::Verdict::Pass => (true, String::new()),
            selftest::Verdict::Fail(detail) => (false, detail),
            selftest::Verdict::Inconclusive => {
                debug!("self-test inconclusive: BPF events were dropped");
                return;
            }
        };
        let before = self
            .health
            .lock()
            .unwrap()
            .selftest
            .replace(heartbeat::SelfTest {
                ok,
                detail: detail.clone(),
            });
        match before {
            None if ok => info!("self-test passed"),
            Some(before) if before.ok && ok => debug!("self-test passed"),
            Some(before) if !before.ok && ok => {
                self.send(
                    "Self-test passed again",
                    "The BPF programs report the canary again.".into(),
                )
                .await
            }
            // Report a failure once, unless it changes.
            Some(before) if !before.ok && before.detail == detail => {
                debug!("self-test still failing: {detail}")
            }
            _ => self.send("Self-test failed", detail).await,
        }
    }

    async fn tamper(&mut self, ev: &Event) {
        self.health.lock().unwrap().tamper_blocked += 1;
        let comm = c_str(&ev.comm);
        let what = tamper_description(ev.dev, ev.ino, &c_str(&ev.name));
        let now = Instant::now();
        let id = (ev.dev, ev.ino, comm.clone());
        if self
            .tamper_reported
            .get(&id)
            .is_some_and(|t| now.duration_since(*t) < TAMPER_REPEAT)
        {
            debug!("tamper attempt blocked again: {what}");
            return;
        }
        self.tamper_reported.insert(id, now);
        self.send(
            "Tamper attempt blocked",
            format!("{what}\nby {comm} (pid {}, uid {})", ev.tgid, ev.uid),
        )
        .await;
    }

    async fn handle_later(&mut self, later: Later) {
        match later {
            Later::Hash { path, who } => self.check_hash(&path, &who).await,
            Later::Resync(path) => self.resync(&path),
            Later::Missing(path) => {
                if self.removed.insert(path.clone()) {
                    self.send(
                        "File removed",
                        format!("{}\n{NOT_WATCHING}", path.display()),
                    )
                    .await
                }
            }
        }
    }

    /// Report the file if its content differs from the database (once per
    /// distinct content).
    async fn check_hash(&mut self, path: &Path, who: &str) {
        let Some(expected) = self.baseline.get(path) else {
            return;
        };
        let hash = match hash_file(path).await {
            Ok(hash) => hash,
            // Removal and renames are reported by their own events.
            Err(err) => {
                debug!("hashing {}: {err}", path.display());
                return;
            }
        };
        if &hash == expected {
            debug!("{} unchanged", path.display());
            self.reported.remove(path);
            return;
        }
        if self.reported.get(path) == Some(&hash) {
            return;
        }
        self.reported.insert(path.to_owned(), hash);
        self.send(
            "Hash mismatch",
            format!("File was modified: {}\nlast written {who}", path.display()),
        )
        .await;
    }

    /// Point the watch for `path` at the inode the path has now (or drop it).
    fn resync(&mut self, path: &Path) {
        let new_key = match std::fs::symlink_metadata(path) {
            Ok(md) if md.file_type().is_file() => Some(inode_key(&md)),
            _ => None,
        };
        let old_key = self.by_path.get(path).copied();
        if old_key == new_key {
            return;
        }
        if let Some(old) = old_key {
            if self.by_key.get(&old).is_some_and(|w| w.path == path) {
                self.by_key.remove(&old);
                if let Err(err) = self.map.remove(&old) {
                    debug!("removing {} from the watch map: {err}", path.display());
                }
            }
            self.by_path.remove(path);
        }
        if let Some(new) = new_key {
            if let Err(err) = self.map.insert(new, WATCH_FILE, 0) {
                warn!("cannot watch {}: {err}", path.display());
                return;
            }
            self.by_key.insert(
                new,
                Watch {
                    path: path.to_owned(),
                    kind: WATCH_FILE,
                },
            );
            self.by_path.insert(path.to_owned(), new);
        }
        debug!("{}: now inode {new_key:?}", path.display());
    }
}
