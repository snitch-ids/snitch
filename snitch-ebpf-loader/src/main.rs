//! `snitch-ebpf-load`: load, attach and pin snitch's BPF programs at boot.
//!
//! Runs in the initramfs after the root file system is mounted and before
//! switch_root, so the programs (including self-protection) are in place
//! before any program from the root file system runs.
//!
//! usage: snitch-ebpf-load --root DIR [--cgroup DIR] [--trusted-exe PATH]...
//!                         [--pin-dir DIR] [--max-watched N]
//!
//!   --root DIR         mount point of the root file system (protected from
//!                      unmounting; init executing from it arms the mount
//!                      rules)
//!   --cgroup DIR       a cgroup2 mount, for attaching the sysctl guard to the
//!                      root cgroup (default: /sys/fs/cgroup if it is one,
//!                      otherwise a temporary mount)
//!   --trusted-exe PATH a program snitch.service may execute, under --root.
//!                      Default: those of DEFAULT_TRUSTED_EXES that exist
//!                      (the snitch binary, systemd-executor). The exec lock
//!                      is on with at least one: nothing else runs in
//!                      snitch.service, and nobody may write to these.
//!   --pin-dir DIR      where to pin (default /sys/fs/bpf/snitch; its parent
//!                      is mounted as bpffs if it isn't one)
//!   --max-watched N    size of the watch map (default 262144)
//!
//! In an initramfs, after mounting the root file system at /sysroot:
//!
//!   snitch-ebpf-load --root /sysroot
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use eyre::{bail, ContextCompat, Result, WrapErr};
use snitch_ebpf_common::InodeKey;
use snitch_ebpf_loader::{
    inode_key, kernel_dev, load, pin_all, program_count, LoadOptions, Protect, DEFAULT_MAX_WATCHED,
    PIN_DIR,
};

const BPF_FS_MAGIC: i64 = 0xcafe_4a11;
const CGROUP2_SUPER_MAGIC: i64 = 0x6367_7270;
/// Programs snitch.service may run, below --root, unless --trusted-exe is
/// given. Missing ones are left out. systemd >= 255 starts every service
/// through systemd-executor.
const DEFAULT_TRUSTED_EXES: &[&str] = &[
    "usr/bin/snitch",
    "usr/local/bin/snitch",
    "usr/lib/systemd/systemd-executor",
    "lib/systemd/systemd-executor",
];
const TEMP_CGROUP: &str = "/run/snitch-cgroup2";

struct Args {
    root: PathBuf,
    cgroup: Option<PathBuf>,
    trusted_exes: Vec<PathBuf>,
    pin_dir: PathBuf,
    max_watched: u32,
}

fn parse_args() -> Result<Args> {
    let mut root = None;
    let mut cgroup = None;
    let mut trusted_exes = Vec::new();
    let mut pin_dir = PathBuf::from(PIN_DIR);
    let mut max_watched = DEFAULT_MAX_WATCHED;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next().wrap_err_with(|| format!("{arg} needs a value"));
        match arg.as_str() {
            "--root" => root = Some(PathBuf::from(value()?)),
            "--cgroup" => cgroup = Some(PathBuf::from(value()?)),
            "--trusted-exe" => trusted_exes.push(PathBuf::from(value()?)),
            "--pin-dir" => pin_dir = PathBuf::from(value()?),
            "--max-watched" => {
                max_watched = value()?.parse().wrap_err("--max-watched")?;
            }
            _ => bail!(
                "unknown argument {arg}\nusage: snitch-ebpf-load --root DIR [--cgroup DIR] \
                 [--trusted-exe PATH]... [--pin-dir DIR] [--max-watched N]"
            ),
        }
    }
    Ok(Args {
        root: root.wrap_err("--root is required")?,
        cgroup,
        trusted_exes,
        pin_dir,
        max_watched,
    })
}

// f_type is i64 on 64-bit glibc targets, but not everywhere.
#[allow(clippy::unnecessary_cast)]
fn fs_magic(path: &Path) -> Result<i64> {
    let c = CString::new(path.as_os_str().as_bytes())?;
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error())
            .wrap_err_with(|| format!("statfs {}", path.display()));
    }
    Ok(st.f_type as i64)
}

fn mount(fstype: &str, target: &Path, data: Option<&str>) -> Result<()> {
    let c_fstype = CString::new(fstype)?;
    let c_target = CString::new(target.as_os_str().as_bytes())?;
    let c_data = data.map(CString::new).transpose()?;
    let data_ptr = c_data
        .as_ref()
        .map_or(std::ptr::null(), |d| d.as_ptr().cast::<libc::c_void>());
    let ret = unsafe {
        libc::mount(
            c_fstype.as_ptr(),
            c_target.as_ptr(),
            c_fstype.as_ptr(),
            0,
            data_ptr,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error())
            .wrap_err_with(|| format!("mounting {fstype} on {}", target.display()));
    }
    Ok(())
}

fn umount(target: &Path) {
    if let Ok(c) = CString::new(target.as_os_str().as_bytes()) {
        unsafe { libc::umount2(c.as_ptr(), 0) };
    }
}

/// Mount bpffs on `dir` unless it is one already.
fn ensure_bpffs(dir: &Path) -> Result<()> {
    if fs_magic(dir).ok() == Some(BPF_FS_MAGIC) {
        return Ok(());
    }
    std::fs::create_dir_all(dir).wrap_err_with(|| format!("creating {}", dir.display()))?;
    mount("bpf", dir, Some("mode=0700"))
}

/// A cgroup2 mount to attach the sysctl guard to. The temporary one is
/// unmounted again (`Some(dir)`), so systemd mounts /sys/fs/cgroup with
/// its own options.
fn cgroup2(arg: Option<&Path>) -> Result<(PathBuf, Option<PathBuf>)> {
    if let Some(dir) = arg {
        return Ok((dir.to_path_buf(), None));
    }
    let sys = Path::new("/sys/fs/cgroup");
    if fs_magic(sys).ok() == Some(CGROUP2_SUPER_MAGIC) {
        return Ok((sys.to_path_buf(), None));
    }
    let temp = PathBuf::from(TEMP_CGROUP);
    std::fs::create_dir_all(&temp).wrap_err_with(|| format!("creating {TEMP_CGROUP}"))?;
    mount("cgroup2", &temp, None)?;
    Ok((temp.clone(), Some(temp)))
}

fn dev_of(path: &Path) -> Result<u32> {
    let md = std::fs::metadata(path).wrap_err_with(|| format!("stat {}", path.display()))?;
    Ok(kernel_dev(md.dev()) as u32)
}

fn run() -> Result<()> {
    if std::mem::size_of::<usize>() != 8 {
        bail!("snitch's BPF programs support 64-bit kernels only");
    }
    let args = parse_args()?;
    let bpffs = args
        .pin_dir
        .parent()
        .wrap_err("--pin-dir needs a parent directory")?;
    ensure_bpffs(bpffs)?;
    if args.pin_dir.exists() {
        bail!("{} exists: already loaded", args.pin_dir.display());
    }
    let trusted = trusted_exes(&args);
    let (cgroup, temp_cgroup) = cgroup2(args.cgroup.as_deref())?;
    let result = load_and_pin(&args, bpffs, &cgroup, &trusted);
    if let Some(temp) = temp_cgroup {
        umount(&temp);
        let _ = std::fs::remove_dir(&temp);
    }
    result
}

/// Inodes of the programs snitch.service may run. A missing one (e.g. an
/// older systemd without systemd-executor) is left out; snitch.service then
/// can't run it.
fn trusted_exes(args: &Args) -> Vec<InodeKey> {
    let explicit = !args.trusted_exes.is_empty();
    let paths: Vec<PathBuf> = if explicit {
        args.trusted_exes.clone()
    } else {
        DEFAULT_TRUSTED_EXES
            .iter()
            .map(|p| args.root.join(p))
            .collect()
    };
    let mut trusted = Vec::new();
    for path in &paths {
        match std::fs::metadata(path) {
            Ok(md) if md.is_file() => {
                let key = inode_key(&md);
                // /lib may be a symlink to /usr/lib
                if !trusted.contains(&key) {
                    trusted.push(key);
                }
            }
            Ok(_) => eprintln!("{} is not a file, not trusted", path.display()),
            Err(err) if explicit => eprintln!("{}: {err}, not trusted", path.display()),
            Err(_) => {}
        }
    }
    trusted
}

fn load_and_pin(args: &Args, bpffs: &Path, cgroup: &Path, trusted: &[InodeKey]) -> Result<()> {
    let protect = Protect {
        root_dev: dev_of(&args.root)?,
        bpffs_dev: dev_of(bpffs)?,
        init_mnt_ns: std::fs::metadata("/proc/self/ns/mnt")
            .wrap_err("stat /proc/self/ns/mnt")?
            .ino() as u32,
        exec_lock: !trusted.is_empty(),
    };
    let bpf = load(&LoadOptions {
        max_watched: args.max_watched,
        protect: Some(protect),
    })?;
    pin_all(bpf, &args.pin_dir, cgroup, trusted)?;
    println!(
        "{} BPF programs attached, pinned in {} (watch map: {} entries, exec lock: {})",
        program_count(),
        args.pin_dir.display(),
        args.max_watched,
        match trusted.len() {
            0 => "off".to_string(),
            n => format!("{n} programs"),
        }
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("snitch-ebpf-load: {err:#}");
            ExitCode::FAILURE
        }
    }
}
