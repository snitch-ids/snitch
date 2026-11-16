//! `snitch-ebpf-load`: load, attach and pin snitch's BPF programs at boot.
//!
//! Runs in the initramfs after the root file system is mounted and before
//! switch_root, so the programs (including self-protection) are in place
//! before any program from the root file system runs.
//!
//! usage: snitch-ebpf-load --root DIR --cgroup DIR [--pin-dir DIR] [--max-watched N]
//!
//!   --root DIR      mount point of the root file system (protected from
//!                   unmounting; init executing from it arms the mount rules)
//!   --cgroup DIR    a cgroup2 mount, for attaching the sysctl guard to the
//!                   root cgroup
//!   --pin-dir DIR   where to pin (default /sys/fs/bpf/snitch; its parent must
//!                   be a bpffs mount)
//!   --max-watched N size of the watch map (default 131072)
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use eyre::{bail, ContextCompat, Result, WrapErr};
use snitch_ebpf_loader::{
    kernel_dev, load, pin_all, program_count, LoadOptions, Protect, DEFAULT_MAX_WATCHED, PIN_DIR,
};

const BPF_FS_MAGIC: i64 = 0xcafe_4a11;

struct Args {
    root: PathBuf,
    cgroup: PathBuf,
    pin_dir: PathBuf,
    max_watched: u32,
}

fn parse_args() -> Result<Args> {
    let mut root = None;
    let mut cgroup = None;
    let mut pin_dir = PathBuf::from(PIN_DIR);
    let mut max_watched = DEFAULT_MAX_WATCHED;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next().wrap_err_with(|| format!("{arg} needs a value"));
        match arg.as_str() {
            "--root" => root = Some(PathBuf::from(value()?)),
            "--cgroup" => cgroup = Some(PathBuf::from(value()?)),
            "--pin-dir" => pin_dir = PathBuf::from(value()?),
            "--max-watched" => {
                max_watched = value()?.parse().wrap_err("--max-watched")?;
            }
            _ => bail!(
                "unknown argument {arg}\nusage: snitch-ebpf-load --root DIR --cgroup DIR \
                 [--pin-dir DIR] [--max-watched N]"
            ),
        }
    }
    Ok(Args {
        root: root.wrap_err("--root is required")?,
        cgroup: cgroup.wrap_err("--cgroup is required")?,
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
    if fs_magic(bpffs)? != BPF_FS_MAGIC {
        bail!("{} is not a bpffs mount", bpffs.display());
    }
    if args.pin_dir.exists() {
        bail!("{} exists: already loaded", args.pin_dir.display());
    }
    let protect = Protect {
        root_dev: dev_of(&args.root)?,
        bpffs_dev: dev_of(bpffs)?,
        init_mnt_ns: std::fs::metadata("/proc/self/ns/mnt")
            .wrap_err("stat /proc/self/ns/mnt")?
            .ino() as u32,
    };
    let bpf = load(&LoadOptions {
        max_watched: args.max_watched,
        protect: Some(protect),
    })?;
    pin_all(bpf, &args.pin_dir, &args.cgroup)?;
    println!(
        "{} BPF programs attached, pinned in {} (watch map: {} entries)",
        program_count(),
        args.pin_dir.display(),
        args.max_watched
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
