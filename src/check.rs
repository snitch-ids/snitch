//! `snitch --check`: what works on this machine and what's missing, with
//! the fix for each.
//!
//! Failures are what keeps snitch from doing its job (no configuration, no
//! database, a backend that rejects the token). Warnings are what makes it
//! weaker than it could be (no BPF LSM, no protection at boot, no
//! heartbeats).

use std::path::Path;
use std::time::Duration;

use chatterbox::dispatcher::{Example, Sender};

use crate::config::{load_config_from_file, Config};

/// Tokens from example configurations (older --demo-config, the default).
const PLACEHOLDER_TOKENS: &[&str] = &["PASTEYOURTOKENHERE", "SDFOIJSDFOIJSDFOIJ"];
use crate::persist::open_database;
use crate::verity::{short, Verity};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Level {
    Ok,
    Info,
    Warn,
    Fail,
}

#[derive(Default)]
struct Report {
    warnings: usize,
    failures: usize,
}

impl Report {
    fn section(&self, name: &str) {
        println!("\n{name}");
    }

    fn item(&mut self, level: Level, text: impl AsRef<str>, fix: Option<String>) {
        let label = match level {
            Level::Ok => "ok",
            Level::Info => "info",
            Level::Warn => {
                self.warnings += 1;
                "warn"
            }
            Level::Fail => {
                self.failures += 1;
                "FAIL"
            }
        };
        println!("  {label:<5} {}", text.as_ref());
        if let Some(fix) = fix {
            println!("        fix: {fix}");
        }
    }
}

/// What the kernel offers for watching with BPF LSM programs.
#[derive(Default)]
struct Kernel {
    btf: bool,
    bpf_lsm: bool,
    /// Has every LSM hook the monitoring programs attach to
    hooks: bool,
    /// Pinned by the loader at boot (protected mode)
    protected: bool,
}

/// Run the checks and print the report. False if something failed.
pub async fn run(config_path: &Path) -> bool {
    let mut r = Report::default();
    println!("snitch {} on {}", env!("CARGO_PKG_VERSION"), platform());

    #[cfg(target_os = "linux")]
    let kernel = linux::kernel(&mut r);
    #[cfg(not(target_os = "linux"))]
    let kernel = Kernel::default();

    let config = configuration(&mut r, config_path);
    if let Some(config) = &config {
        verity(&mut r, config);
        database(&mut r, config);
        backend(&mut r, config).await;
    }
    #[cfg(target_os = "linux")]
    linux::daemon(&mut r);

    mode(&kernel);
    println!();
    match (r.failures, r.warnings) {
        (0, 0) => println!("All checks passed."),
        (f, w) => println!("{f} failed, {w} warnings."),
    }
    r.failures == 0
}

fn platform() -> String {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let os = match std::env::consts::OS {
        "linux" => "Linux",
        "macos" => "macOS",
        "windows" => "Windows",
        other => other,
    };
    format!("{os} {} ({})", release.trim(), std::env::consts::ARCH).replace("  ", " ")
}

fn configuration(r: &mut Report, path: &Path) -> Option<Config> {
    r.section("Configuration");
    if !path.exists() {
        r.item(
            Level::Fail,
            format!("{} doesn't exist", path.display()),
            Some(format!(
                "snitch --demo-config > {} prints a template to start from",
                path.display()
            )),
        );
        return None;
    }
    let config = match load_config_from_file(path) {
        Ok(config) => config,
        Err(err) => {
            r.item(Level::Fail, format!("{}: {err:#}", path.display()), None);
            return None;
        }
    };
    let digest = config
        .origin
        .as_ref()
        .map(|o| format!(" (sha256 {})", &o.sha256[..12]))
        .unwrap_or_default();
    r.item(Level::Ok, format!("{}{digest}", path.display()), None);
    if config.directories.is_empty() {
        r.item(
            Level::Warn,
            "no directories to watch",
            Some("list them under directories: (e.g. /etc and /usr)".into()),
        );
    }
    for dir in &config.directories {
        if Path::new(dir).is_dir() {
            r.item(Level::Ok, format!("watches {dir}"), None);
        } else {
            r.item(
                Level::Warn,
                format!("{dir} (in directories:) doesn't exist"),
                None,
            );
        }
    }
    // Left over from an older --demo-config: chatterbox fails to send.
    let example = Sender::example();
    let senders = [
        (
            "telegram",
            config.sender.telegram.is_some() && config.sender.telegram == example.telegram,
        ),
        (
            "email",
            config.sender.email.is_some() && config.sender.email == example.email,
        ),
        (
            "slack",
            config.sender.slack.is_some() && config.sender.slack == example.slack,
        ),
    ];
    for (name, _) in senders.iter().filter(|(_, is_example)| *is_example) {
        r.item(
            Level::Warn,
            format!("sender: {name} has the example values, so sending fails"),
            Some(format!("fill in real ones, or remove {name}")),
        );
    }
    Some(config)
}

/// dm-verity file systems below the watched directories.
fn verity(r: &mut Report, config: &Config) {
    r.section("dm-verity");
    let verity = Verity::detect(&config.directories());
    for m in &verity.mounts {
        r.item(
            Level::Ok,
            format!(
                "{} (root hash {}{}): its files aren't hashed; the backend alerts when the \
                 root hash changes",
                m.mount,
                short(&m.root_hash),
                if m.signed { ", signed" } else { "" }
            ),
            None,
        );
        if m.corrupted {
            r.item(
                Level::Fail,
                format!("{}: dm-verity found blocks that don't match", m.mount),
                Some(
                    "the disk was modified or is failing; see the kernel log (journalctl -k \
                     | grep verity)"
                        .into(),
                ),
            );
        }
    }
    for line in &verity.ignored {
        r.item(
            Level::Warn,
            format!("{line}; snitch hashes its files"),
            Some("set it up without ignore_corruption".into()),
        );
    }
    if let Some(err) = &verity.error {
        r.item(Level::Warn, err.clone(), None);
    } else if verity.is_empty() && verity.ignored.is_empty() {
        r.item(
            Level::Info,
            "none below the watched directories: snitch hashes and watches all their files \
             (standalone)",
            None,
        );
    }
}

fn database(r: &mut Report, config: &Config) {
    r.section("Hash database");
    if !Path::new(&config.snitch_root).is_absolute() {
        r.item(
            Level::Fail,
            format!("snitch_root {} isn't an absolute path", config.snitch_root),
            None,
        );
        return;
    }
    let path = config.database_path();
    if !path.exists() {
        r.item(
            Level::Fail,
            format!("no hash database at {}", path.display()),
            Some(
                "snitch --init, while the system is in a known-good state (or build it with \
                 the image: snitch --init --root)"
                    .into(),
            ),
        );
        return;
    }
    match open_database(&path) {
        Ok(db) => r.item(
            Level::Ok,
            format!("{}: {} files", path.display(), db.len()),
            None,
        ),
        Err(err) => r.item(
            Level::Warn,
            format!("{}: can't open it: {err}", path.display()),
            None,
        ),
    }
}

async fn backend(r: &mut Report, config: &Config) {
    r.section("Backend");
    let token = config.token.trim();
    let get_token = "a token from your snitch backend (e.g. snitch.cool), as token: in the \
                     configuration";
    if token.is_empty() {
        r.item(
            Level::Warn,
            "no token: messages are only logged, and nobody notices when snitch stops (no \
             heartbeats)",
            Some(get_token.into()),
        );
        return;
    }
    if PLACEHOLDER_TOKENS.contains(&token) {
        r.item(
            Level::Fail,
            "token: is still the placeholder",
            Some(get_token.into()),
        );
        return;
    }
    let base = config.url.trim_end_matches('/');
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            r.item(Level::Fail, format!("HTTP client: {err}"), None);
            return;
        }
    };
    match client
        .get(format!("{base}/heartbeat"))
        .bearer_auth(token)
        .send()
        .await
    {
        Ok(resp) => match resp.status().as_u16() {
            200 | 204 => r.item(Level::Ok, format!("{base} accepts the token"), None),
            401 => r.item(
                Level::Fail,
                format!("{base} rejects the token"),
                Some("check token: in the configuration".into()),
            ),
            404 | 405 => r.item(
                Level::Warn,
                format!("{base} is reachable, but can't check the token (older backend)"),
                None,
            ),
            status => r.item(
                Level::Warn,
                format!("{base}: unexpected HTTP status {status}"),
                None,
            ),
        },
        Err(err) => r.item(
            Level::Fail,
            format!("can't reach {base}: {}", error_chain(&err)),
            Some("check url: in the configuration, and the network".into()),
        ),
    }
    match config.heartbeat_interval {
        0 => r.item(
            Level::Warn,
            "heartbeats are off (heartbeat_interval: 0): nobody notices when snitch stops",
            Some("heartbeat_interval: 60".into()),
        ),
        n => {
            let n = n.clamp(10, 3600);
            r.item(
                Level::Ok,
                format!(
                    "heartbeat every {n} s: the backend alerts after about {} s without one",
                    2 * n + 30
                ),
                None,
            )
        }
    }
}

/// An error with its causes: "error sending request: ...: Connection refused".
fn error_chain(err: &dyn std::error::Error) -> String {
    let mut text = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        let cause_text = cause.to_string();
        if !text.contains(&cause_text) {
            text.push_str(": ");
            text.push_str(&cause_text);
        }
        source = cause.source();
    }
    text
}

/// What `snitch --watch` would do here.
fn mode(kernel: &Kernel) {
    println!("\nMode");
    let text = if !cfg!(all(feature = "ebpf", target_os = "linux")) {
        "snitch --watch uses inotify: this snitch has no BPF support. It reports changes, \
         but not who made them."
    } else if kernel.protected {
        "snitch --watch uses BPF LSM programs, protected: loaded at boot, so root can't stop \
         snitch or detach them."
    } else if kernel.btf && kernel.bpf_lsm && kernel.hooks {
        "snitch --watch uses BPF LSM programs, unprotected: snitch loads them itself, so root \
         can stop it (the backend notices with heartbeats)."
    } else {
        "snitch --watch uses inotify: no BPF LSM here (see Kernel). It reports changes, but \
         not who made them."
    };
    println!("  {text}");
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{Kernel, Level, Report};
    use std::path::Path;

    const BTF: &str = "/sys/kernel/btf/vmlinux";
    const LSM: &str = "/sys/kernel/security/lsm";
    const LOCKDOWN: &str = "/sys/kernel/security/lockdown";

    pub(super) fn kernel(r: &mut Report) -> Kernel {
        let mut k = Kernel::default();
        r.section("Kernel");
        if effective_uid() != Some(0) {
            r.item(
                Level::Warn,
                "not running as root: some checks can't look everywhere",
                Some("sudo snitch --check".into()),
            );
        }

        k.btf = Path::new(BTF).exists();
        if k.btf {
            r.item(Level::Ok, format!("kernel BTF ({BTF})"), None);
        } else {
            r.item(
                Level::Warn,
                "no kernel BTF: BPF LSM programs need it",
                Some("a kernel with CONFIG_DEBUG_INFO_BTF=y".into()),
            );
        }

        match std::fs::read_to_string(LSM) {
            Ok(list) => {
                let list = list.trim();
                k.bpf_lsm = list.split(',').any(|l| l == "bpf");
                if k.bpf_lsm {
                    r.item(Level::Ok, format!("BPF LSM active (LSMs: {list})"), None);
                } else {
                    let fix = format!(
                        "add lsm={} to the kernel command line and reboot (GRUB: \
                         GRUB_CMDLINE_LINUX in /etc/default/grub, then update-grub or \
                         grub2-mkconfig)",
                        lsm_param(list)
                    );
                    match bpf_lsm_built() {
                        Some(false) => r.item(
                            Level::Warn,
                            "the kernel has no BPF LSM (CONFIG_BPF_LSM)",
                            Some("a kernel with CONFIG_BPF_LSM=y".into()),
                        ),
                        Some(true) => r.item(
                            Level::Warn,
                            format!("BPF LSM built in, but not active (LSMs: {list})"),
                            Some(fix),
                        ),
                        None => r.item(
                            Level::Warn,
                            format!("BPF LSM not active (LSMs: {list})"),
                            Some(format!("if the kernel has CONFIG_BPF_LSM=y: {fix}")),
                        ),
                    }
                }
            }
            Err(err) => r.item(
                Level::Warn,
                format!("can't read {LSM}: {err} (securityfs not mounted?)"),
                None,
            ),
        }

        k.hooks = hooks(r, k.btf);

        r.section("Protection");
        protection(r, &mut k);
        k
    }

    /// The LSM hooks snitch's programs attach to (older kernels lack some).
    fn hooks(r: &mut Report, btf: bool) -> bool {
        #[cfg(feature = "ebpf")]
        if btf && bpf_lsm_built() == Some(true) {
            let missing = |protect| snitch_ebpf_loader::missing_lsm_hooks(protect);
            match (missing(false), missing(true)) {
                (Ok(monitor), _) if !monitor.is_empty() => {
                    r.item(
                        Level::Warn,
                        format!(
                            "the kernel lacks LSM hooks for file monitoring: {}",
                            monitor.join(", ")
                        ),
                        Some("a newer kernel (snitch is tested with 6.8 and later)".into()),
                    );
                    return false;
                }
                (Ok(_), Ok(all)) if !all.is_empty() => r.item(
                    Level::Warn,
                    format!(
                        "the kernel lacks LSM hooks for self-protection: {}",
                        all.join(", ")
                    ),
                    Some("a newer kernel (snitch is tested with 6.8 and later)".into()),
                ),
                (Ok(_), Ok(_)) => r.item(Level::Ok, "LSM hooks for all of snitch's programs", None),
                (Err(err), _) | (_, Err(err)) => {
                    r.item(
                        Level::Warn,
                        format!("can't check the LSM hooks: {err:#}"),
                        None,
                    );
                    return false;
                }
            }
            return true;
        }
        let _ = (r, btf);
        true
    }

    fn protection(r: &mut Report, k: &mut Kernel) {
        #[cfg(feature = "ebpf")]
        {
            let pins = snitch_ebpf_loader::PIN_DIR;
            match std::fs::read_dir(pins) {
                Ok(entries) => {
                    let n = entries.count();
                    k.protected = Path::new(pins).join("map_CONTROL").exists();
                    if k.protected {
                        r.item(
                            Level::Ok,
                            format!("BPF programs loaded at boot ({n} pins in {pins})"),
                            None,
                        );
                    } else {
                        r.item(
                            Level::Warn,
                            format!("{pins} exists, but without snitch's maps"),
                            None,
                        );
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => r.item(
                    Level::Warn,
                    "not loaded at boot: snitch --watch runs without self-protection",
                    Some(
                        "load the BPF programs from the initramfs with snitch-ebpf-load \
                         (see README, \"Protection at boot\")"
                            .into(),
                    ),
                ),
                Err(err) => r.item(Level::Info, format!("can't look into {pins}: {err}"), None),
            }
        }
        #[cfg(not(feature = "ebpf"))]
        {
            let _ = &k;
            r.item(
                Level::Info,
                "this snitch was built without BPF support (cargo feature `ebpf`)",
                None,
            );
        }

        match std::fs::read_to_string(LOCKDOWN) {
            Ok(modes) => {
                let mode = selected(&modes).unwrap_or("unknown");
                let weak = mode == "none";
                match (k.protected, weak) {
                    (true, true) => r.item(
                        Level::Warn,
                        "lockdown is off: root can load unsigned kernel modules or write kernel \
                         memory, and get around the protection",
                        Some(
                            "boot with lockdown=integrity and signed modules (with UEFI secure \
                             boot, many distributions turn it on)"
                                .into(),
                        ),
                    ),
                    (true, false) => r.item(Level::Ok, format!("lockdown: {mode}"), None),
                    (false, _) => r.item(Level::Info, format!("lockdown: {mode}"), None),
                }
            }
            Err(_) => r.item(Level::Info, "lockdown: not available", None),
        }
    }

    pub(super) fn daemon(r: &mut Report) {
        r.section("snitch");
        let me = std::process::id();
        let mut found = Vec::new();
        if let Ok(procs) = std::fs::read_dir("/proc") {
            for entry in procs.flatten() {
                let Some(pid) = entry
                    .file_name()
                    .to_str()
                    .and_then(|p| p.parse::<u32>().ok())
                else {
                    continue;
                };
                if pid == me {
                    continue;
                }
                let Ok(cmdline) = std::fs::read(entry.path().join("cmdline")) else {
                    continue;
                };
                let args: Vec<String> = cmdline
                    .split(|&b| b == 0)
                    .filter(|a| !a.is_empty())
                    .map(|a| String::from_utf8_lossy(a).into_owned())
                    .collect();
                let is_snitch = args
                    .first()
                    .is_some_and(|a| Path::new(a).file_name().is_some_and(|f| f == "snitch"));
                let watches = args.iter().skip(1).any(|a| {
                    matches!(
                        a.as_str(),
                        "--watch"
                            | "--watch-ebpf"
                            | "--watch-files"
                            | "-w"
                            | "--watch-authentications"
                    )
                });
                if is_snitch && watches {
                    found.push(format!("pid {pid}: {}", args.join(" ")));
                }
            }
        }
        if found.is_empty() {
            r.item(
                Level::Warn,
                "snitch isn't running",
                Some("systemctl enable --now snitch.service".into()),
            );
        }
        for f in found {
            r.item(Level::Ok, format!("running: {f}"), None);
        }
    }

    /// Whether the kernel has the BPF LSM built in, from its BTF (None:
    /// can't tell).
    fn bpf_lsm_built() -> Option<bool> {
        #[cfg(feature = "ebpf")]
        return snitch_ebpf_loader::kernel_has_bpf_lsm().ok();
        #[cfg(not(feature = "ebpf"))]
        None
    }

    fn effective_uid() -> Option<u32> {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        let line = status.lines().find(|l| l.starts_with("Uid:"))?;
        line.split_whitespace().nth(2)?.parse().ok()
    }

    /// The `lsm=` value that keeps the active LSMs and adds bpf.
    pub(super) fn lsm_param(active: &str) -> String {
        let mut lsms: Vec<&str> = active
            .split(',')
            .map(str::trim)
            .filter(|l| !l.is_empty() && *l != "capability")
            .collect();
        lsms.push("bpf");
        lsms.join(",")
    }

    /// The selected entry of a securityfs choice list: "none [integrity]
    /// confidentiality" -> "integrity".
    pub(super) fn selected(list: &str) -> Option<&str> {
        let start = list.find('[')? + 1;
        let end = start + list[start..].find(']')?;
        Some(&list[start..end])
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn lsm_param_keeps_the_active_lsms() {
            assert_eq!(
                lsm_param("lockdown,capability,landlock,yama,apparmor\n".trim()),
                "lockdown,landlock,yama,apparmor,bpf"
            );
        }

        #[test]
        fn selected_lockdown_mode() {
            assert_eq!(
                selected("none [integrity] confidentiality\n"),
                Some("integrity")
            );
            assert_eq!(selected("[none] integrity confidentiality"), Some("none"));
            assert_eq!(selected("none"), None);
        }
    }
}
