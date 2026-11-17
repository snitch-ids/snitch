//! Self-test: catches ways to disarm snitch that its protection doesn't
//! know about.
//!
//! Every minute, snitch writes a canary file that is in the watch map and
//! expects the BPF programs to report the open for writing and the close.
//! With the programs loaded at boot, it also tries to remove a protected
//! pin and expects that to be refused and reported. Whatever is missing when
//! the next round starts fails the self-test: the programs were detached or
//! disarmed (e.g. `kernel.ftrace_enabled=0` without the guard), or
//! self-protection is off.

use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use aya::maps::{HashMap, MapData};
use snitch_ebpf_common::{
    Event, InodeKey, EV_CLOSE_WRITE, EV_INODE_FREED, EV_OPEN_WRITE, EV_TAMPER, TAMPER_PIN_UNLINK,
    WATCH_FILE,
};
use snitch_ebpf_loader::{inode_key, PIN_DIR, SELFTEST_PIN};

use super::c_str;

/// On tmpfs and outside the watched directories, so writing it reports
/// nothing else.
const CANARY: &str = "/run/snitch/canary";
pub const INTERVAL: Duration = Duration::from_secs(60);

const SEEN_OPEN: u8 = 1;
const SEEN_CLOSE: u8 = 2;
const SEEN_REFUSED: u8 = 4;

#[derive(Debug, PartialEq)]
pub enum Verdict {
    Pass,
    Fail(String),
    /// BPF events were dropped during the round: can't tell.
    Inconclusive,
}

struct Round {
    expect: u8,
    seen: u8,
    dropped: u64,
}

pub struct SelfTest {
    canary: PathBuf,
    key: Option<InodeKey>,
    pin: Option<PathBuf>,
    pin_removed: bool,
    tgid: u32,
    round: Option<Round>,
    count: u64,
}

impl SelfTest {
    pub fn new(protected: bool) -> Self {
        let pin = Path::new(PIN_DIR).join(SELFTEST_PIN);
        let pin = match protected {
            true if pin.exists() => Some(pin),
            true => {
                info!(
                    "no {}: the initramfs is from an older snitch, so self-protection isn't \
                     part of the self-test",
                    pin.display()
                );
                None
            }
            false => None,
        };
        Self {
            canary: PathBuf::from(CANARY),
            key: None,
            pin,
            pin_removed: false,
            tgid: std::process::id(),
            round: None,
            count: 0,
        }
    }

    /// What the self-test covers, for the log.
    pub fn scope(&self) -> &'static str {
        match self.pin {
            Some(_) => "file monitoring and self-protection",
            None => "file monitoring",
        }
    }

    /// Start a round. Returns the verdict on the previous round if it
    /// didn't complete, or on this one if it failed right away.
    pub fn start(
        &mut self,
        map: &mut HashMap<MapData, InodeKey, u32>,
        dropped: u64,
    ) -> Option<Verdict> {
        let previous = self
            .round
            .take()
            .map(|round| self.timed_out(round, dropped));

        let mut problems = Vec::new();
        let mut expect = 0;
        match self.write_canary(map) {
            Ok(()) => expect |= SEEN_OPEN | SEEN_CLOSE,
            Err(err) => problems.push(format!(
                "writing the canary {}: {err}",
                self.canary.display()
            )),
        }
        if let Some(pin) = &self.pin {
            if self.pin_removed {
                problems.push(format!(
                    "self-protection is off: the protected pin {} could be removed",
                    pin.display()
                ));
            } else {
                match std::fs::remove_file(pin) {
                    Err(err) if err.kind() == ErrorKind::PermissionDenied => expect |= SEEN_REFUSED,
                    Ok(()) => {
                        self.pin_removed = true;
                        problems.push(format!(
                            "self-protection is off: removing the protected pin {} succeeded",
                            pin.display()
                        ));
                    }
                    Err(err) => problems.push(format!(
                        "removing the protected pin {}: {err} (expected \"Operation not \
                         permitted\")",
                        pin.display()
                    )),
                }
            }
        }
        if !problems.is_empty() {
            return Some(Verdict::Fail(problems.join("\n")));
        }
        self.round = Some(Round {
            expect,
            seen: 0,
            dropped,
        });
        previous
    }

    fn timed_out(&self, round: Round, dropped: u64) -> Verdict {
        if dropped > round.dropped {
            return Verdict::Inconclusive;
        }
        let missing = round.expect & !round.seen;
        let what = match (missing & SEEN_OPEN != 0, missing & SEEN_CLOSE != 0) {
            (true, true) => Some("writing"),
            (true, false) => Some("opening for writing"),
            (false, true) => Some("closing after writing"),
            (false, false) => None,
        };
        let mut detail = String::new();
        if let Some(what) = what {
            detail = format!(
                "the BPF programs did not report {what} the canary {} within {} s: file \
                 monitoring is not working (programs detached or disarmed)",
                self.canary.display(),
                INTERVAL.as_secs()
            );
        }
        if missing & SEEN_REFUSED != 0 {
            if !detail.is_empty() {
                detail.push('\n');
            }
            detail.push_str("removing the protected pin was refused, but not reported");
        }
        Verdict::Fail(detail)
    }

    fn write_canary(&mut self, map: &mut HashMap<MapData, InodeKey, u32>) -> std::io::Result<()> {
        if let Some(dir) = self.canary.parent() {
            std::fs::create_dir_all(dir)?;
        }
        // Created (or replaced) before it's in the watch map: no events.
        let md = match std::fs::symlink_metadata(&self.canary) {
            Ok(md) if md.file_type().is_file() => md,
            _ => {
                let _ = std::fs::remove_file(&self.canary);
                std::fs::File::create(&self.canary)?;
                std::fs::symlink_metadata(&self.canary)?
            }
        };
        let key = inode_key(&md);
        if self.key != Some(key) {
            if let Some(old) = self.key.take() {
                let _ = map.remove(&old);
            }
            map.insert(key, WATCH_FILE, 0)
                .map_err(std::io::Error::other)?;
            self.key = Some(key);
        }
        self.count += 1;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.canary)?;
        writeln!(file, "snitch self-test {}", self.count)?;
        Ok(())
    }

    /// Whether the event belongs to the self-test (and isn't reported).
    pub fn owns(&self, ev: &Event) -> bool {
        if ev.kind == EV_TAMPER {
            return ev.tgid == self.tgid
                && ev.dev == TAMPER_PIN_UNLINK
                && c_str(&ev.name) == SELFTEST_PIN;
        }
        self.key
            == Some(InodeKey {
                dev: ev.dev,
                ino: ev.ino,
            })
    }

    /// Record an event the self-test owns. `Some(Pass)` when the round is
    /// complete.
    pub fn record(&mut self, ev: &Event) -> Option<Verdict> {
        let seen = match ev.kind {
            EV_TAMPER => SEEN_REFUSED,
            EV_INODE_FREED => {
                // Deleted: the next round creates it again.
                self.key = None;
                return None;
            }
            _ if ev.tgid != self.tgid => {
                warn!(
                    "{} (snitch's self-test canary): event {} by {} (pid {})",
                    self.canary.display(),
                    ev.kind,
                    c_str(&ev.comm),
                    ev.tgid
                );
                return None;
            }
            EV_OPEN_WRITE => SEEN_OPEN,
            EV_CLOSE_WRITE => SEEN_CLOSE,
            _ => return None,
        };
        let round = self.round.as_mut()?;
        round.seen |= seen;
        if round.seen & round.expect == round.expect {
            self.round = None;
            return Some(Verdict::Pass);
        }
        None
    }
}
