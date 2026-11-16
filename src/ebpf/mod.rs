//! `snitch --watch-ebpf`: file monitoring with BPF LSM programs (monitor
//! mode).
//!
//! The programs in `snitch-ebpf` run on the LSM hooks for writes,
//! truncation, unlink, rename, hard links, creation, chmod and chown. They
//! report operations on the files in the hash database and on entries of the
//! configured directories, identified by (device, inode). This module loads
//! them, fills their watch map, and turns their events into messages. A file
//! that was opened for writing is hashed again when the writer closes it, and
//! reported if the hash differs from the database.
mod btf;

use std::collections::HashMap as StdHashMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use aya::maps::{HashMap, MapData, PerCpuArray, RingBuf};
use aya::programs::Lsm;
use aya::{Btf as AyaBtf, EbpfLoader};
use eyre::{bail, ContextCompat, Result, WrapErr};
use snitch_ebpf_common::{
    Event, InodeKey, EV_CHMOD, EV_CHOWN, EV_CLOSE_WRITE, EV_CREATE, EV_LINK, EV_OPEN_WRITE,
    EV_RENAME_FROM, EV_RENAME_OVER, EV_TRUNCATE, EV_UNLINK, STAT_DROPPED, STAT_READ_ERRORS,
    WATCH_DIR, WATCH_FILE,
};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use walkdir::WalkDir;

use crate::config::Config;
use crate::dispatcher::{MessageBackend, SnitchDispatcher};
use crate::hashing::hash_file;
use crate::persist::open_database;

static BPF_OBJ: &[u8] = aya::include_bytes_aligned!(env!("SNITCH_BPF_OBJECT"));

/// LSM hooks with a program in `snitch-ebpf` (program name = hook name).
const PROGRAMS: &[&str] = &[
    "file_open",
    "file_release",
    "path_truncate",
    "path_chmod",
    "path_chown",
    "path_unlink",
    "path_rename",
    "path_link",
    "path_mknod",
    "path_mkdir",
    "path_symlink",
];

/// Hash a file again this long after it was opened for writing, in case the
/// writer keeps it open.
const OPEN_WRITE_RECHECK: Duration = Duration::from_secs(5);
/// LSM hooks run before the operation; look at the result this much later.
const AFTER_OPERATION: Duration = Duration::from_secs(1);
const STATS_INTERVAL: Duration = Duration::from_secs(30);

/// Values for the programs' `OFF_*` globals: member offsets of the kernel
/// structs they read, from the running kernel's BTF.
fn struct_offsets() -> Result<Vec<(&'static str, u32)>> {
    let btf = btf::Btf::from_file(Path::new("/sys/kernel/btf/vmlinux"))
        .wrap_err("reading kernel BTF (needs CONFIG_DEBUG_INFO_BTF)")?;
    let get = |s: &str, m: &str, size: u32| -> Result<u32> {
        let member = btf.member(s, m)?;
        if member.size != size {
            bail!(
                "{s}.{m} has size {}, the BPF programs read {size}",
                member.size
            );
        }
        Ok(member.offset)
    };
    Ok(vec![
        ("OFF_FILE_F_MODE", get("file", "f_mode", 4)?),
        ("OFF_FILE_F_INODE", get("file", "f_inode", 8)?),
        ("OFF_INODE_I_INO", get("inode", "i_ino", 8)?),
        ("OFF_INODE_I_SB", get("inode", "i_sb", 8)?),
        ("OFF_SB_S_DEV", get("super_block", "s_dev", 4)?),
        ("OFF_PATH_DENTRY", get("path", "dentry", 8)?),
        ("OFF_DENTRY_D_INODE", get("dentry", "d_inode", 8)?),
        (
            "OFF_DENTRY_D_NAME_NAME",
            get("dentry", "d_name", 16)? + get("qstr", "name", 8)?,
        ),
    ])
}

/// Userspace `st_dev` (glibc encoding) to the kernel's internal `dev_t`.
fn kernel_dev(st_dev: u64) -> u64 {
    let major = ((st_dev >> 8) & 0xfff) | ((st_dev >> 32) & 0xffff_f000);
    let minor = (st_dev & 0xff) | ((st_dev >> 12) & 0xffff_ff00);
    (major << 20) | minor
}

fn inode_key(md: &std::fs::Metadata) -> InodeKey {
    InodeKey {
        dev: kernel_dev(md.dev()),
        ino: md.ino(),
    }
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
}

struct Monitor<'a> {
    dispatcher: &'a SnitchDispatcher,
    map: HashMap<MapData, InodeKey, u32>,
    by_key: StdHashMap<InodeKey, Watch>,
    by_path: StdHashMap<PathBuf, InodeKey>,
    baseline: StdHashMap<PathBuf, String>,
    /// Last mismatching hash reported per file, to report each change once.
    reported: StdHashMap<PathBuf, String>,
    later: mpsc::UnboundedSender<Later>,
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

    // Room for files that get a new inode while we run.
    let max_entries = (by_key.len() + by_key.len() / 4 + 1024) as u32;
    let offsets = struct_offsets()?;
    let mut loader = EbpfLoader::new();
    loader.map_max_entries("WATCHED", max_entries);
    for (name, value) in &offsets {
        loader.override_global(name, value, true);
    }
    let mut bpf = loader.load(BPF_OBJ).wrap_err("loading the BPF object")?;

    let btf = AyaBtf::from_sys_fs().wrap_err("reading kernel BTF")?;
    for name in PROGRAMS {
        let prog: &mut Lsm = bpf
            .program_mut(name)
            .wrap_err_with(|| format!("BPF program {name} missing"))?
            .try_into()?;
        prog.load(name, &btf)
            .wrap_err_with(|| format!("loading BPF LSM program {name}"))?;
    }

    let mut map: HashMap<MapData, InodeKey, u32> =
        HashMap::try_from(bpf.take_map("WATCHED").wrap_err("map WATCHED missing")?)?;
    for (key, watch) in &by_key {
        map.insert(key, watch.kind, 0)?;
    }

    for name in PROGRAMS {
        let prog: &mut Lsm = bpf.program_mut(name).unwrap().try_into()?;
        prog.attach()
            .wrap_err_with(|| format!("attaching BPF LSM program {name}"))?;
    }
    info!("watching {n_files} files and {n_dirs} directories with BPF LSM programs");

    let events = RingBuf::try_from(bpf.take_map("EVENTS").wrap_err("map EVENTS missing")?)?;
    let mut events = AsyncFd::new(events)?;
    let stats: PerCpuArray<MapData, u64> =
        PerCpuArray::try_from(bpf.take_map("STATS").wrap_err("map STATS missing")?)?;
    let (later_tx, mut later_rx) = mpsc::unbounded_channel();
    let mut monitor = Monitor {
        dispatcher,
        map,
        by_key,
        by_path,
        baseline,
        reported: StdHashMap::new(),
        later: later_tx,
    };

    let mut stats_tick = tokio::time::interval(STATS_INTERVAL);
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
            _ = stats_tick.tick() => {
                let dropped = stat_total(&stats, STAT_DROPPED)?;
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
            other => warn!("unknown BPF event kind {other}"),
        }
    }

    async fn handle_later(&mut self, later: Later) {
        match later {
            Later::Hash { path, who } => self.check_hash(&path, &who).await,
            Later::Resync(path) => self.resync(&path),
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

#[cfg(test)]
mod tests {
    use super::kernel_dev;

    #[test]
    fn kernel_dev_encoding() {
        // makedev(253, 0) in glibc's encoding -> MKDEV(253, 0) in the kernel
        assert_eq!(kernel_dev(0xfd00), 253 << 20);
        // makedev(259, 3): major above 255 uses the high bits
        let glibc = ((259u64 & 0xfff) << 8) | 3;
        assert_eq!(kernel_dev(glibc), (259 << 20) | 3);
        // minor above 255
        let glibc = (8u64 << 8) | (0x123 & 0xff) | ((0x123 & !0xff) << 12);
        assert_eq!(kernel_dev(glibc), (8 << 20) | 0x123);
    }
}
