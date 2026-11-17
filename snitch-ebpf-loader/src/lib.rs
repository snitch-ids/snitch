//! Loads snitch's BPF programs (`snitch-ebpf`, embedded) with the struct
//! offsets of the running kernel.
//!
//! - Boot: `snitch-ebpf-load` runs in the initramfs, before any program from
//!   the root file system. It loads all programs, attaches them, and pins
//!   links and maps in bpffs ([`pin_all`]). The pins keep everything
//!   attached after it exits; the self-protection programs keep the pins in
//!   place. `snitch --watch-ebpf` then claims the pinned maps.
//! - Fallback: without pins (no snitch initramfs), `snitch --watch-ebpf` loads
//!   and attaches the file monitoring programs itself ([`load`],
//!   [`attach_monitor`]). They stay attached while the process runs, and
//!   nothing protects them.
//!
//! Rust BPF programs can't emit CO-RE relocations yet: the kernel struct
//! member offsets they need are globals, set here from the kernel's BTF.
mod btf;
mod rawbpf;

use std::fs;
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use aya::maps::{Array, HashMap, Map, MapData};
use aya::programs::{links::FdLink, CgroupSysctl, Lsm};
use aya::{Btf as AyaBtf, Ebpf, EbpfLoader};
use eyre::{bail, ContextCompat, Result, WrapErr};
use snitch_ebpf_common::{InodeKey, ABI_VERSION, CTL_ABI};

pub static BPF_OBJ: &[u8] = aya::include_bytes_aligned!(env!("SNITCH_BPF_OBJECT"));

/// Where the boot loader pins links (`link_<program>`) and maps
/// (`map_<NAME>`).
pub const PIN_DIR: &str = "/sys/fs/bpf/snitch";

/// Maps the daemon uses.
pub const DAEMON_MAPS: &[&str] = &["WATCHED", "EVENTS", "STATS", "CONTROL"];
/// A spare, protected pin (`CONTROL` pinned a second time) for snitch's
/// self-test: removing it must fail with `EPERM` and report a tamper
/// attempt. If protection is broken, only this duplicate pin goes away.
pub const SELFTEST_PIN: &str = "selftest";
/// Maps nobody may open once the daemon has claimed its maps. `.rodata`
/// (the offsets and protection settings) is frozen; protected anyway.
const PROTECTED_MAP_NAMES: &[&str] = &[
    ".rodata",
    "WATCHED",
    "EVENTS",
    "STATS",
    "CONTROL",
    "PROTECTED",
    "PROTECTED_MAPS",
    "TRUSTED_EXES",
];

/// `WATCHED` size when loaded at boot, before the database is known. The map
/// isn't preallocated, so unused entries cost nothing.
pub const DEFAULT_MAX_WATCHED: u32 = 131_072;

/// File monitoring: LSM programs (program name = hook name).
pub const MONITOR_PROGRAMS: &[&str] = &[
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
    "inode_free_security",
];

/// Self-protection: LSM programs (program, hook), attached at boot only.
/// Plus the cgroup/sysctl program `sysctl_guard`.
pub const PROTECT_PROGRAMS: &[(&str, &str)] = &[
    ("bpf", "bpf"),
    ("bpf_map", "bpf_map"),
    ("sb_umount", "sb_umount"),
    ("sb_mount", "sb_mount"),
    ("move_mount", "move_mount"),
    ("sb_pivotroot", "sb_pivotroot"),
    ("bprm_check_security", "bprm_check_security"),
    ("task_kill", "task_kill"),
    ("ptrace_access_check", "ptrace_access_check"),
    ("protect_mmap_file", "mmap_file"),
    ("protect_file_open", "file_open"),
    ("protect_path_truncate", "path_truncate"),
];

/// What the self-protection programs guard.
#[derive(Debug, Clone, Copy)]
pub struct Protect {
    /// Kernel dev_t of the root file system
    pub root_dev: u32,
    /// Kernel dev_t of the bpffs holding the pins
    pub bpffs_dev: u32,
    /// Inode number of the initial mount namespace
    pub init_mnt_ns: u32,
    /// Exec lock for snitch.service: only the programs given to [`pin_all`]
    /// may run there, and nobody may write to them.
    pub exec_lock: bool,
}

pub struct LoadOptions {
    pub max_watched: u32,
    /// Load the self-protection programs too (boot only).
    pub protect: Option<Protect>,
}

/// Userspace `st_dev` (glibc encoding) to the kernel's internal `dev_t`.
pub fn kernel_dev(st_dev: u64) -> u64 {
    let major = ((st_dev >> 8) & 0xfff) | ((st_dev >> 32) & 0xffff_f000);
    let minor = (st_dev & 0xff) | ((st_dev >> 12) & 0xffff_ff00);
    (major << 20) | minor
}

pub fn inode_key(md: &fs::Metadata) -> InodeKey {
    InodeKey {
        dev: kernel_dev(md.dev()),
        ino: md.ino(),
    }
}

/// Values for the programs' `OFF_*` globals: member offsets of the kernel
/// structs they read, from the running kernel's BTF.
pub fn struct_offsets() -> Result<Vec<(&'static str, u32)>> {
    let btf = btf::Btf::from_file(Path::new("/sys/kernel/btf/vmlinux"))
        .wrap_err("reading kernel BTF (needs CONFIG_DEBUG_INFO_BTF)")?;
    let get = |s: &str, m: &str, size: u32| -> Result<u32> {
        // `old|new`: a member that was renamed
        let member = match m.split_once('|') {
            Some((new, old)) => btf.member(s, new).or_else(|_| btf.member(s, old))?,
            None => btf.member(s, m)?,
        };
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
        ("OFF_INODE_I_NLINK", get("inode", "i_nlink", 4)?),
        ("OFF_SB_S_DEV", get("super_block", "s_dev", 4)?),
        ("OFF_SB_S_MAGIC", get("super_block", "s_magic", 8)?),
        ("OFF_PATH_MNT", get("path", "mnt", 8)?),
        ("OFF_PATH_DENTRY", get("path", "dentry", 8)?),
        ("OFF_DENTRY_D_INODE", get("dentry", "d_inode", 8)?),
        (
            "OFF_DENTRY_D_NAME_NAME",
            get("dentry", "d_name", 16)? + get("qstr", "name", 8)?,
        ),
        ("OFF_TASK_TGID", get("task_struct", "tgid", 4)?),
        ("OFF_TASK_NSPROXY", get("task_struct", "nsproxy", 8)?),
        ("OFF_NSPROXY_MNT_NS", get("nsproxy", "mnt_ns", 8)?),
        (
            "OFF_MNT_NS_INUM",
            btf.member("mnt_namespace", "ns")?.offset + get("ns_common", "inum", 4)?,
        ),
        ("OFF_VFSMOUNT_MNT_SB", get("vfsmount", "mnt_sb", 8)?),
        ("OFF_BPRM_FILE", get("linux_binprm", "file", 8)?),
        ("OFF_BPF_MAP_ID", get("bpf_map", "id", 4)?),
        ("OFF_BPRM_FILENAME", get("linux_binprm", "filename", 8)?),
        (
            "OFF_FILE_F_PATH_DENTRY",
            get("file", "f_path", 16)? + get("path", "dentry", 8)?,
        ),
        ("OFF_TASK_CGROUPS", get("task_struct", "cgroups", 8)?),
        ("OFF_CSS_SET_DFL_CGRP", get("css_set", "dfl_cgrp", 8)?),
        ("OFF_CGROUP_KN", get("cgroup", "kn", 8)?),
        ("OFF_KERNFS_NODE_NAME", get("kernfs_node", "name", 8)?),
        // Renamed in 6.15
        (
            "OFF_KERNFS_NODE_PARENT",
            get("kernfs_node", "__parent|parent", 8)?,
        ),
        ("OFF_MOUNT_MNT", btf.member("mount", "mnt")?.offset),
        ("OFF_MOUNT_MNT_NS", get("mount", "mnt_ns", 8)?),
        (
            "OFF_MOUNT_MNT_MOUNTPOINT",
            get("mount", "mnt_mountpoint", 8)?,
        ),
        ("OFF_DENTRY_D_PARENT", get("dentry", "d_parent", 8)?),
    ])
}

/// Load the BPF object and its LSM programs (not attached).
pub fn load(opts: &LoadOptions) -> Result<Ebpf> {
    let offsets = struct_offsets()?;
    let mut loader = EbpfLoader::new();
    loader.map_max_entries("WATCHED", opts.max_watched);
    for (name, value) in &offsets {
        loader.override_global(name, value, true);
    }
    let p = opts.protect.unwrap_or(Protect {
        root_dev: 0,
        bpffs_dev: 0,
        init_mnt_ns: 0,
        exec_lock: false,
    });
    loader.override_global("ROOT_DEV", &p.root_dev, true);
    loader.override_global("BPFFS_DEV", &p.bpffs_dev, true);
    loader.override_global("INIT_MNT_NS", &p.init_mnt_ns, true);
    let exec_lock = p.exec_lock as u32;
    loader.override_global("EXEC_LOCK", &exec_lock, true);
    let mut bpf = loader.load(BPF_OBJ).wrap_err("loading the BPF object")?;

    let btf = AyaBtf::from_sys_fs().wrap_err("reading kernel BTF")?;
    let monitor = MONITOR_PROGRAMS.iter().map(|name| (*name, *name));
    let protect = PROTECT_PROGRAMS
        .iter()
        .copied()
        .filter(|_| opts.protect.is_some());
    for (name, hook) in monitor.chain(protect) {
        let prog: &mut Lsm = bpf
            .program_mut(name)
            .wrap_err_with(|| format!("BPF program {name} missing"))?
            .try_into()?;
        prog.load(hook, &btf)
            .wrap_err_with(|| format!("loading BPF LSM program {name}"))?;
    }
    if opts.protect.is_some() {
        let prog: &mut CgroupSysctl = bpf
            .program_mut("sysctl_guard")
            .wrap_err("BPF program sysctl_guard missing")?
            .try_into()?;
        prog.load().wrap_err("loading BPF program sysctl_guard")?;
    }
    Ok(bpf)
}

/// Attach the file monitoring programs. They stay attached while `bpf` lives.
pub fn attach_monitor(bpf: &mut Ebpf) -> Result<()> {
    for name in MONITOR_PROGRAMS {
        let prog: &mut Lsm = bpf.program_mut(name).unwrap().try_into()?;
        prog.attach()
            .wrap_err_with(|| format!("attaching BPF LSM program {name}"))?;
    }
    Ok(())
}

fn map_data<'a>(bpf: &'a Ebpf, name: &str) -> Result<&'a MapData> {
    match bpf
        .map(name)
        .wrap_err_with(|| format!("map {name} missing"))?
    {
        Map::Array(m) | Map::HashMap(m) | Map::PerCpuArray(m) | Map::RingBuf(m) => Ok(m),
        _ => bail!("map {name} has an unexpected type"),
    }
}

/// Number of programs [`pin_all`] attaches.
pub fn program_count() -> usize {
    MONITOR_PROGRAMS.len() + PROTECT_PROGRAMS.len() + 1
}

/// Boot: attach all programs from a [`load`] with `protect`, pin links and
/// the daemon's maps under `pin_dir`, and fill the protection maps.
/// `cgroup_root`: a cgroup2 mount, for the cgroup/sysctl program.
/// `trusted_exes`: the programs snitch.service may run (exec lock).
pub fn pin_all(
    mut bpf: Ebpf,
    pin_dir: &Path,
    cgroup_root: &Path,
    trusted_exes: &[InodeKey],
) -> Result<()> {
    fs::create_dir_all(pin_dir).wrap_err_with(|| format!("creating {}", pin_dir.display()))?;
    let pin = |name: String| -> PathBuf { pin_dir.join(name) };

    for name in DAEMON_MAPS {
        bpf.map(name)
            .unwrap()
            .pin(pin(format!("map_{name}")))
            .wrap_err_with(|| format!("pinning map {name}"))?;
    }
    bpf.map("CONTROL")
        .unwrap()
        .pin(pin(SELFTEST_PIN.into()))
        .wrap_err("pinning the self-test pin")?;

    let protect = PROTECT_PROGRAMS.iter().map(|(name, _)| name);
    for name in MONITOR_PROGRAMS.iter().chain(protect) {
        let prog: &mut Lsm = bpf.program_mut(name).unwrap().try_into()?;
        let id = prog
            .attach()
            .wrap_err_with(|| format!("attaching BPF LSM program {name}"))?;
        let link: FdLink = prog.take_link(id)?.into();
        link.pin(pin(format!("link_{name}")))
            .wrap_err_with(|| format!("pinning link {name}"))?;
    }

    // aya 0.14 can't pin cgroup links and passes BPF_F_ALLOW_MULTI, which
    // links reject; create and pin this one directly. Cgroup links are
    // always multi-attach: programs further down the tree run in addition
    // and can't override it.
    let prog: &mut CgroupSysctl = bpf.program_mut("sysctl_guard").unwrap().try_into()?;
    let cg = fs::File::open(cgroup_root)
        .wrap_err_with(|| format!("opening cgroup {}", cgroup_root.display()))?;
    let link = rawbpf::link_create(prog.fd()?.as_fd(), cg.as_fd(), rawbpf::BPF_CGROUP_SYSCTL, 0)
        .wrap_err("attaching sysctl_guard to the root cgroup")?;
    rawbpf::obj_pin(link.as_fd(), &pin("link_sysctl_guard".into()))
        .wrap_err("pinning link sysctl_guard")?;

    let mut ids = Vec::new();
    for name in PROTECTED_MAP_NAMES {
        ids.push(map_data(&bpf, name)?.info()?.id());
    }
    let mut protected_maps: HashMap<_, u32, u32> =
        HashMap::try_from(bpf.map_mut("PROTECTED_MAPS").unwrap())?;
    for id in ids {
        protected_maps.insert(id, 1, 0)?;
    }

    let mut control: Array<_, u32> = Array::try_from(bpf.map_mut("CONTROL").unwrap())?;
    control.set(CTL_ABI, ABI_VERSION, 0)?;

    let mut trusted: HashMap<_, InodeKey, u32> =
        HashMap::try_from(bpf.map_mut("TRUSTED_EXES").unwrap())?;
    for key in trusted_exes {
        trusted.insert(key, 1, 0)?;
    }

    let mut protected: HashMap<_, InodeKey, u32> =
        HashMap::try_from(bpf.map_mut("PROTECTED").unwrap())?;
    protected.insert(inode_key(&fs::metadata(pin_dir)?), 1, 0)?;
    for entry in fs::read_dir(pin_dir)? {
        let entry = entry?;
        protected.insert(inode_key(&entry.metadata()?), 1, 0)?;
    }
    Ok(())
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
