//! snitch's BPF LSM programs.
//!
//! File monitoring (monitor mode, never refuses): report changes to watched
//! files and to entries of watched directories. Watched inodes are keyed by
//! (kernel dev_t, inode number) in `WATCHED`, filled by `snitch
//! --watch-ebpf` from the hash database. Events go to `EVENTS`.
//!
//! Self-protection (refuses, see "Self-protection" below): attached by
//! `snitch-ebpf-load` from the initramfs, keeps root from detaching the
//! programs, removing their pins, or blinding the daemon.
//!
//! Rust can't emit CO-RE relocations yet, so the struct member offsets are
//! read-only globals that the loader sets from the running kernel's BTF
//! before loading. The verifier sees them as constants.
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes,
        generated::{bpf_get_current_task, bpf_sysctl_get_name},
    },
    macros::{cgroup_sysctl, lsm, map},
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::{LsmContext, SysctlContext},
};
use snitch_ebpf_common::{
    Event, InodeKey, CTL_ARMED, CTL_DAEMON_TGID, CTL_LEN, CTL_LOCKED, EV_CHMOD, EV_CHOWN,
    EV_CLOSE_WRITE, EV_CREATE, EV_INODE_FREED, EV_LINK, EV_OPEN_WRITE, EV_RENAME_FROM,
    EV_RENAME_OVER, EV_TAMPER, EV_TRUNCATE, EV_UNLINK, NAME_LEN, STAT_DENIED, STAT_DROPPED,
    STAT_EVENTS, STAT_LEN, STAT_READ_ERRORS, TAMPER_BPF_CMD, TAMPER_KILL, TAMPER_MAP_FD,
    TAMPER_MOVE_MOUNT, TAMPER_PIN_RENAME, TAMPER_PIN_UNLINK, TAMPER_PIVOT_ROOT, TAMPER_PTRACE,
    TAMPER_SYSCTL, TAMPER_UMOUNT, WATCH_DIR, WATCH_FILE,
};

// Set by the loader from /sys/kernel/btf/vmlinux.
#[no_mangle]
static OFF_FILE_F_MODE: u32 = 0;
#[no_mangle]
static OFF_FILE_F_INODE: u32 = 0;
#[no_mangle]
static OFF_INODE_I_INO: u32 = 0;
#[no_mangle]
static OFF_INODE_I_SB: u32 = 0;
#[no_mangle]
static OFF_INODE_I_NLINK: u32 = 0;
#[no_mangle]
static OFF_SB_S_DEV: u32 = 0;
#[no_mangle]
static OFF_PATH_DENTRY: u32 = 0;
#[no_mangle]
static OFF_DENTRY_D_INODE: u32 = 0;
/// `dentry.d_name.name`
#[no_mangle]
static OFF_DENTRY_D_NAME_NAME: u32 = 0;
#[no_mangle]
static OFF_SB_S_MAGIC: u32 = 0;
#[no_mangle]
static OFF_TASK_TGID: u32 = 0;
#[no_mangle]
static OFF_TASK_NSPROXY: u32 = 0;
#[no_mangle]
static OFF_NSPROXY_MNT_NS: u32 = 0;
/// `mnt_namespace.ns.inum`
#[no_mangle]
static OFF_MNT_NS_INUM: u32 = 0;
#[no_mangle]
static OFF_VFSMOUNT_MNT_SB: u32 = 0;
#[no_mangle]
static OFF_PATH_MNT: u32 = 0;
#[no_mangle]
static OFF_BPRM_FILE: u32 = 0;
#[no_mangle]
static OFF_BPF_MAP_ID: u32 = 0;

// Set by snitch-ebpf-load (boot): what to protect.
/// Kernel dev_t of the root file system
#[no_mangle]
static ROOT_DEV: u32 = 0;
/// Kernel dev_t of the bpffs that holds snitch's pins
#[no_mangle]
static BPFFS_DEV: u32 = 0;
/// Inode number of the initial mount namespace
#[no_mangle]
static INIT_MNT_NS: u32 = 0;

/// Resized by the loader. No preallocation: the boot loader sizes it
/// generously before the database is known.
#[map]
static WATCHED: HashMap<InodeKey, u32> = HashMap::with_max_entries(1024, BPF_F_NO_PREALLOC);

/// snitch's pins and their directory (filled by the boot loader)
#[map]
static PROTECTED: HashMap<InodeKey, u32> = HashMap::with_max_entries(64, 0);

/// Ids of snitch's maps (filled by the boot loader)
#[map]
static PROTECTED_MAPS: HashMap<u32, u32> = HashMap::with_max_entries(16, 0);

/// See `CTL_*`.
#[map]
static CONTROL: Array<u32> = Array::with_max_entries(CTL_LEN, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(STAT_LEN, 0);

const FMODE_WRITE: u32 = 0x2;
const BPF_F_NO_PREALLOC: u32 = 1;
const EPERM: i32 = 1;

type R<T> = Result<T, i64>;

#[inline(always)]
fn off(v: &u32) -> usize {
    // read_volatile keeps the compiler from folding the 0 initializer.
    unsafe { core::ptr::read_volatile(v) as usize }
}

#[inline(always)]
fn bump(idx: u32) {
    if let Some(p) = STATS.get_ptr_mut(idx) {
        unsafe { *p += 1 };
    }
}

#[inline(always)]
unsafe fn read<T>(base: *const u8, off: usize) -> R<T> {
    bpf_probe_read_kernel(base.add(off) as *const T).map_err(|e| e as i64)
}

#[inline(always)]
unsafe fn inode_key(inode: *const u8) -> R<Option<InodeKey>> {
    if inode.is_null() {
        return Ok(None);
    }
    // i_ino is `unsigned long`: 64-bit kernels only for now.
    let ino: u64 = read(inode, off(&OFF_INODE_I_INO))?;
    let sb: *const u8 = read(inode, off(&OFF_INODE_I_SB))?;
    let dev: u32 = read(sb, off(&OFF_SB_S_DEV))?;
    Ok(Some(InodeKey {
        dev: dev as u64,
        ino,
    }))
}

/// Key of the inode behind `dentry` if it is in `WATCHED` with one of `flags`.
/// Negative dentries (no inode yet) are never watched.
#[inline(always)]
unsafe fn watched_dentry(dentry: *const u8, flags: u32) -> R<Option<InodeKey>> {
    if dentry.is_null() {
        return Ok(None);
    }
    let inode: *const u8 = read(dentry, off(&OFF_DENTRY_D_INODE))?;
    let Some(key) = inode_key(inode)? else {
        return Ok(None);
    };
    Ok(match WATCHED.get(&key) {
        Some(v) if *v & flags != 0 => Some(key),
        _ => None,
    })
}

/// Like `watched_dentry` for a `struct path *`.
#[inline(always)]
unsafe fn watched_path(path: *const u8, flags: u32) -> R<Option<InodeKey>> {
    let dentry: *const u8 = read(path, off(&OFF_PATH_DENTRY))?;
    watched_dentry(dentry, flags)
}

/// Send an event for `key`. `name_of`: dentry whose name goes into the event,
/// or null.
#[inline(always)]
unsafe fn emit(kind: u32, key: InodeKey, name_of: *const u8) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let mut ev = Event {
        kind,
        tgid: (pid_tgid >> 32) as u32,
        pid: pid_tgid as u32,
        uid: bpf_get_current_uid_gid() as u32,
        dev: key.dev,
        ino: key.ino,
        comm: bpf_get_current_comm().unwrap_or([0u8; 16]),
        name: [0u8; NAME_LEN],
    };
    if !name_of.is_null() {
        match read::<*const u8>(name_of, off(&OFF_DENTRY_D_NAME_NAME)) {
            Ok(name) => {
                let _ = bpf_probe_read_kernel_str_bytes(name, &mut ev.name);
            }
            Err(_) => bump(STAT_READ_ERRORS),
        }
    }
    match EVENTS.output::<Event>(&ev, 0) {
        Ok(()) => bump(STAT_EVENTS),
        Err(_) => bump(STAT_DROPPED),
    }
}

/// Monitor mode: never refuse. A failed kernel read is counted, not fatal.
#[inline(always)]
fn verdict(r: R<()>) -> i32 {
    if r.is_err() {
        bump(STAT_READ_ERRORS);
    }
    0
}

/// For hooks that may refuse. A failed kernel read allows the operation and
/// is counted: wrong offsets must not make the system unusable.
#[inline(always)]
fn guarded(r: R<i32>) -> i32 {
    match r {
        Ok(v) => v,
        Err(_) => {
            bump(STAT_READ_ERRORS);
            0
        }
    }
}

/// Refuse a tamper attempt: count it, report it, return -EPERM.
#[inline(always)]
unsafe fn tamper(what: u64, detail: u64, name_of: *const u8) -> i32 {
    bump(STAT_DENIED);
    emit(
        EV_TAMPER,
        InodeKey {
            dev: what,
            ino: detail,
        },
        name_of,
    );
    -EPERM
}

/// Value of a `u32` global set by the loader.
#[inline(always)]
fn cfg(v: &u32) -> u32 {
    unsafe { core::ptr::read_volatile(v) }
}

#[inline(always)]
fn ctl(idx: u32) -> u32 {
    CONTROL.get(idx).copied().unwrap_or(0)
}

#[inline(always)]
fn current_tgid() -> u32 {
    (bpf_get_current_pid_tgid() >> 32) as u32
}

/// Whether `dentry` is one of snitch's pins (or their directory).
#[inline(always)]
unsafe fn protected_dentry(dentry: *const u8) -> R<bool> {
    if dentry.is_null() {
        return Ok(false);
    }
    let inode: *const u8 = read(dentry, off(&OFF_DENTRY_D_INODE))?;
    let Some(key) = inode_key(inode)? else {
        return Ok(false);
    };
    Ok(PROTECTED.get(&key).is_some())
}

// Each `int` hook gets the verdict of earlier BPF LSM programs as its last
// argument; a non-zero verdict is passed through and the operation won't
// happen, so there is nothing to report.

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    let prev: i32 = ctx.arg(1);
    if prev != 0 {
        return prev;
    }
    verdict(unsafe { file_write_event(&ctx, EV_OPEN_WRITE) })
}

/// Last reference to an open file dropped: the writer is done.
#[lsm(hook = "file_release")]
pub fn file_release(ctx: LsmContext) -> i32 {
    verdict(unsafe { file_write_event(&ctx, EV_CLOSE_WRITE) })
}

#[inline(always)]
unsafe fn file_write_event(ctx: &LsmContext, kind: u32) -> R<()> {
    let file: *const u8 = ctx.arg(0);
    let f_mode: u32 = read(file, off(&OFF_FILE_F_MODE))?;
    if f_mode & FMODE_WRITE == 0 {
        return Ok(());
    }
    let inode: *const u8 = read(file, off(&OFF_FILE_F_INODE))?;
    if let Some(key) = inode_key(inode)? {
        if let Some(v) = WATCHED.get(&key) {
            if *v & WATCH_FILE != 0 {
                emit(kind, key, core::ptr::null());
            }
        }
    }
    Ok(())
}

#[lsm(hook = "path_truncate")]
pub fn path_truncate(ctx: LsmContext) -> i32 {
    let prev: i32 = ctx.arg(1);
    if prev != 0 {
        return prev;
    }
    verdict(unsafe { path_event(ctx.arg(0), EV_TRUNCATE) })
}

#[lsm(hook = "path_chmod")]
pub fn path_chmod(ctx: LsmContext) -> i32 {
    let prev: i32 = ctx.arg(2);
    if prev != 0 {
        return prev;
    }
    verdict(unsafe { path_event(ctx.arg(0), EV_CHMOD) })
}

#[lsm(hook = "path_chown")]
pub fn path_chown(ctx: LsmContext) -> i32 {
    let prev: i32 = ctx.arg(3);
    if prev != 0 {
        return prev;
    }
    verdict(unsafe { path_event(ctx.arg(0), EV_CHOWN) })
}

#[inline(always)]
unsafe fn path_event(path: *const u8, kind: u32) -> R<()> {
    let flags = match kind {
        EV_TRUNCATE => WATCH_FILE,
        _ => WATCH_FILE | WATCH_DIR,
    };
    if let Some(key) = watched_path(path, flags)? {
        emit(kind, key, core::ptr::null());
    }
    Ok(())
}

#[lsm(hook = "path_unlink")]
pub fn path_unlink(ctx: LsmContext) -> i32 {
    let prev: i32 = ctx.arg(2);
    if prev != 0 {
        return prev;
    }
    guarded(unsafe { try_path_unlink(&ctx) })
}

#[inline(always)]
unsafe fn try_path_unlink(ctx: &LsmContext) -> R<i32> {
    let dentry: *const u8 = ctx.arg(1);
    if protected_dentry(dentry)? {
        return Ok(tamper(TAMPER_PIN_UNLINK, 0, dentry));
    }
    if let Some(key) = watched_dentry(dentry, WATCH_FILE)? {
        emit(EV_UNLINK, key, dentry);
    }
    Ok(0)
}

#[lsm(hook = "path_rename")]
pub fn path_rename(ctx: LsmContext) -> i32 {
    let prev: i32 = ctx.arg(5);
    if prev != 0 {
        return prev;
    }
    guarded(unsafe { try_path_rename(&ctx) })
}

#[inline(always)]
unsafe fn try_path_rename(ctx: &LsmContext) -> R<i32> {
    let old_dentry: *const u8 = ctx.arg(1);
    let new_dir: *const u8 = ctx.arg(2);
    let new_dentry: *const u8 = ctx.arg(3);
    // Renaming onto a pin replaces (unpins) it.
    if protected_dentry(old_dentry)? || protected_dentry(new_dentry)? {
        return Ok(tamper(TAMPER_PIN_RENAME, 0, old_dentry));
    }
    let from = watched_dentry(old_dentry, WATCH_FILE)?;
    if let Some(key) = from {
        emit(EV_RENAME_FROM, key, new_dentry);
    }
    if let Some(key) = watched_dentry(new_dentry, WATCH_FILE)? {
        emit(EV_RENAME_OVER, key, old_dentry);
    } else if from.is_none() {
        // A watched file moving in is already reported as renamed.
        if let Some(key) = watched_path(new_dir, WATCH_DIR)? {
            emit(EV_CREATE, key, new_dentry);
        }
    }
    Ok(0)
}

#[lsm(hook = "path_link")]
pub fn path_link(ctx: LsmContext) -> i32 {
    let prev: i32 = ctx.arg(3);
    if prev != 0 {
        return prev;
    }
    verdict(unsafe { try_path_link(&ctx) })
}

#[inline(always)]
unsafe fn try_path_link(ctx: &LsmContext) -> R<()> {
    let old_dentry: *const u8 = ctx.arg(0);
    let new_dir: *const u8 = ctx.arg(1);
    let new_dentry: *const u8 = ctx.arg(2);
    if let Some(key) = watched_dentry(old_dentry, WATCH_FILE)? {
        emit(EV_LINK, key, new_dentry);
    } else if let Some(key) = watched_path(new_dir, WATCH_DIR)? {
        emit(EV_CREATE, key, new_dentry);
    }
    Ok(())
}

/// Also called for `open(O_CREAT)` of a new file.
#[lsm(hook = "path_mknod")]
pub fn path_mknod(ctx: LsmContext) -> i32 {
    let prev: i32 = ctx.arg(4);
    if prev != 0 {
        return prev;
    }
    verdict(unsafe { create_event(&ctx) })
}

#[lsm(hook = "path_mkdir")]
pub fn path_mkdir(ctx: LsmContext) -> i32 {
    let prev: i32 = ctx.arg(3);
    if prev != 0 {
        return prev;
    }
    verdict(unsafe { create_event(&ctx) })
}

#[lsm(hook = "path_symlink")]
pub fn path_symlink(ctx: LsmContext) -> i32 {
    let prev: i32 = ctx.arg(3);
    if prev != 0 {
        return prev;
    }
    verdict(unsafe { create_event(&ctx) })
}

/// `(const struct path *dir, struct dentry *dentry, ...)` hooks
#[inline(always)]
unsafe fn create_event(ctx: &LsmContext) -> R<()> {
    let dir: *const u8 = ctx.arg(0);
    let dentry: *const u8 = ctx.arg(1);
    if let Some(key) = watched_path(dir, WATCH_DIR)? {
        emit(EV_CREATE, key, dentry);
    }
    Ok(())
}

/// An inode is destroyed: evicted from the inode cache, or deleted. Only a
/// deleted inode (no links left) gives up its inode number, which the file
/// system may hand to the next new file; drop it from `WATCHED` so that file
/// isn't reported under the deleted file's name.
#[lsm(hook = "inode_free_security")]
pub fn inode_free_security(ctx: LsmContext) -> i32 {
    verdict(unsafe { try_inode_free(&ctx) })
}

#[inline(always)]
unsafe fn try_inode_free(ctx: &LsmContext) -> R<()> {
    let inode: *const u8 = ctx.arg(0);
    let Some(key) = inode_key(inode)? else {
        return Ok(());
    };
    if WATCHED.get(&key).is_none() {
        return Ok(());
    }
    let nlink: u32 = read(inode, off(&OFF_INODE_I_NLINK))?;
    if nlink == 0 {
        let _ = WATCHED.remove(&key);
        emit(EV_INODE_FREED, key, core::ptr::null());
    }
    Ok(())
}

// Self-protection
//
// Attached by snitch-ebpf-load from the initramfs, before any program from
// the root file system runs. The pins in snitch's bpffs keep the programs
// attached and the maps alive without a process; these programs keep root
// from removing them or blinding the daemon. They refuse (-EPERM) regardless
// of monitor mode and report each attempt (EV_TAMPER). What they can't stop
// (e.g. `systemctl stop snitch`) is left to the heartbeat.

const BPF_LINK_UPDATE: u64 = 29;
const BPF_LINK_DETACH: u64 = 34;
const MS_MOVE: u64 = 8192;
const SYSFS_MAGIC: u64 = 0x6265_6572;
const PTRACE_MODE_ATTACH: u64 = 0x02;

/// Whether the current task is in the initial mount namespace. Mount
/// operations act on the caller's namespace; in other namespaces they only
/// affect copies (e.g. systemd's per-service namespaces).
#[inline(always)]
unsafe fn in_init_mnt_ns() -> R<bool> {
    let init = cfg(&INIT_MNT_NS);
    if init == 0 {
        return Ok(false);
    }
    let task = bpf_get_current_task() as *const u8;
    let nsproxy: *const u8 = read(task, off(&OFF_TASK_NSPROXY))?;
    if nsproxy.is_null() {
        return Ok(false);
    }
    let mnt_ns: *const u8 = read(nsproxy, off(&OFF_NSPROXY_MNT_NS))?;
    let inum: u32 = read(mnt_ns, off(&OFF_MNT_NS_INUM))?;
    Ok(inum == init)
}

/// `s_magic` of `sb` if unmounting or moving it would release snitch's pins:
/// snitch's bpffs, or a file system above it (sysfs, the root file system).
/// Detaching a parent lazily takes the bpffs mount with it.
#[inline(always)]
unsafe fn protected_sb(sb: *const u8) -> R<Option<u64>> {
    let dev: u32 = read(sb, off(&OFF_SB_S_DEV))?;
    let magic: u64 = read(sb, off(&OFF_SB_S_MAGIC))?;
    let bpffs = cfg(&BPFFS_DEV);
    let root = cfg(&ROOT_DEV);
    if (bpffs != 0 && dev == bpffs) || (root != 0 && dev == root) || magic == SYSFS_MAGIC {
        Ok(Some(magic))
    } else {
        Ok(None)
    }
}

/// `bpf(cmd, attr, size, kernel)`: refuse detaching or replacing links. With
/// an fd for one of snitch's links (BPF_OBJ_GET on its pin,
/// BPF_LINK_GET_FD_BY_ID) these commands would remove or replace the program
/// although the pin stays. The hook only sees an fd number, so this applies
/// to all links.
#[lsm(hook = "bpf")]
pub fn bpf(ctx: LsmContext) -> i32 {
    let prev: i32 = ctx.arg(4);
    if prev != 0 {
        return prev;
    }
    let cmd: u64 = ctx.arg::<u64>(0) & 0xffff_ffff;
    let kernel: u64 = ctx.arg::<u64>(3) & 0xff;
    if kernel == 0 && (cmd == BPF_LINK_UPDATE || cmd == BPF_LINK_DETACH) {
        return unsafe { tamper(TAMPER_BPF_CMD, cmd, core::ptr::null()) };
    }
    0
}

/// `bpf_map(map, fmode)`, on every new map fd (BPF_OBJ_GET of a pin,
/// BPF_MAP_GET_FD_BY_ID): once the daemon holds fds for snitch's maps, nobody
/// gets another one. With one, root could empty WATCHED or drain EVENTS.
#[lsm(hook = "bpf_map")]
pub fn bpf_map(ctx: LsmContext) -> i32 {
    let prev: i32 = ctx.arg(2);
    if prev != 0 {
        return prev;
    }
    guarded(unsafe { try_bpf_map(&ctx) })
}

#[inline(always)]
unsafe fn try_bpf_map(ctx: &LsmContext) -> R<i32> {
    if ctl(CTL_LOCKED) == 0 {
        return Ok(0);
    }
    let map: *const u8 = ctx.arg(0);
    let id: u32 = read(map, off(&OFF_BPF_MAP_ID))?;
    if PROTECTED_MAPS.get(&id).is_some() {
        return Ok(tamper(TAMPER_MAP_FD, id as u64, core::ptr::null()));
    }
    Ok(0)
}

/// `sb_umount(mnt, flags)`
#[lsm(hook = "sb_umount")]
pub fn sb_umount(ctx: LsmContext) -> i32 {
    let prev: i32 = ctx.arg(2);
    if prev != 0 {
        return prev;
    }
    guarded(unsafe { try_sb_umount(&ctx) })
}

#[inline(always)]
unsafe fn try_sb_umount(ctx: &LsmContext) -> R<i32> {
    if !in_init_mnt_ns()? {
        return Ok(0);
    }
    let mnt: *const u8 = ctx.arg(0);
    let sb: *const u8 = read(mnt, off(&OFF_VFSMOUNT_MNT_SB))?;
    if let Some(magic) = protected_sb(sb)? {
        return Ok(tamper(TAMPER_UMOUNT, magic, core::ptr::null()));
    }
    Ok(0)
}

/// `sb_mount(dev_name, path, type, flags, data)`: refuse MS_MOVE after boot.
/// The hook only gets the source as a string, so all moves in the initial
/// namespace are refused. (The initramfs moves /sys, /proc, /dev and /run
/// into the root file system before this arms.)
#[lsm(hook = "sb_mount")]
pub fn sb_mount(ctx: LsmContext) -> i32 {
    let prev: i32 = ctx.arg(5);
    if prev != 0 {
        return prev;
    }
    guarded(unsafe { try_sb_mount(&ctx) })
}

#[inline(always)]
unsafe fn try_sb_mount(ctx: &LsmContext) -> R<i32> {
    let flags: u64 = ctx.arg(3);
    if flags & MS_MOVE == 0 || ctl(CTL_ARMED) == 0 || !in_init_mnt_ns()? {
        return Ok(0);
    }
    Ok(tamper(TAMPER_MOVE_MOUNT, flags, core::ptr::null()))
}

/// `move_mount(from_path, to_path)` (new mount API)
#[lsm(hook = "move_mount")]
pub fn move_mount(ctx: LsmContext) -> i32 {
    let prev: i32 = ctx.arg(2);
    if prev != 0 {
        return prev;
    }
    guarded(unsafe { try_move_mount(&ctx) })
}

#[inline(always)]
unsafe fn try_move_mount(ctx: &LsmContext) -> R<i32> {
    if ctl(CTL_ARMED) == 0 || !in_init_mnt_ns()? {
        return Ok(0);
    }
    let from: *const u8 = ctx.arg(0);
    let mnt: *const u8 = read(from, off(&OFF_PATH_MNT))?;
    let sb: *const u8 = read(mnt, off(&OFF_VFSMOUNT_MNT_SB))?;
    if protected_sb(sb)?.is_some() {
        return Ok(tamper(TAMPER_MOVE_MOUNT, 0, core::ptr::null()));
    }
    Ok(0)
}

/// `sb_pivotroot(old_path, new_path)`
#[lsm(hook = "sb_pivotroot")]
pub fn sb_pivotroot(ctx: LsmContext) -> i32 {
    let prev: i32 = ctx.arg(2);
    if prev != 0 {
        return prev;
    }
    guarded(unsafe { try_sb_pivotroot() })
}

#[inline(always)]
unsafe fn try_sb_pivotroot() -> R<i32> {
    if ctl(CTL_ARMED) == 0 || !in_init_mnt_ns()? {
        return Ok(0);
    }
    Ok(tamper(TAMPER_PIVOT_ROOT, 0, core::ptr::null()))
}

/// `bprm_check_security(bprm)`: arms the mount rules when init (pid 1)
/// executes a program from the root file system, i.e. after switch_root.
/// Never refuses.
#[lsm(hook = "bprm_check_security")]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    let prev: i32 = ctx.arg(1);
    if prev != 0 {
        return prev;
    }
    verdict(unsafe { try_arm(&ctx) })
}

#[inline(always)]
unsafe fn try_arm(ctx: &LsmContext) -> R<()> {
    let root = cfg(&ROOT_DEV);
    if root == 0 || current_tgid() != 1 || ctl(CTL_ARMED) != 0 {
        return Ok(());
    }
    let bprm: *const u8 = ctx.arg(0);
    let file: *const u8 = read(bprm, off(&OFF_BPRM_FILE))?;
    let inode: *const u8 = read(file, off(&OFF_FILE_F_INODE))?;
    let sb: *const u8 = read(inode, off(&OFF_INODE_I_SB))?;
    let dev: u32 = read(sb, off(&OFF_SB_S_DEV))?;
    if dev == root {
        if let Some(armed) = CONTROL.get_ptr_mut(CTL_ARMED) {
            *armed = 1;
        }
    }
    Ok(())
}

/// `task_kill(p, info, sig, cred)`: only init and the daemon itself may
/// signal the daemon. Kernel-generated signals (OOM, cgroup.kill) don't come
/// through here.
#[lsm(hook = "task_kill")]
pub fn task_kill(ctx: LsmContext) -> i32 {
    let prev: i32 = ctx.arg(4);
    if prev != 0 {
        return prev;
    }
    guarded(unsafe { try_task_kill(&ctx) })
}

#[inline(always)]
unsafe fn try_task_kill(ctx: &LsmContext) -> R<i32> {
    let sig: u64 = ctx.arg::<u64>(2) & 0xffff_ffff;
    let daemon = ctl(CTL_DAEMON_TGID);
    if sig == 0 || daemon == 0 {
        return Ok(0);
    }
    let p: *const u8 = ctx.arg(0);
    let target: u32 = read(p, off(&OFF_TASK_TGID))?;
    let me = current_tgid();
    if target != daemon || me == 1 || me == daemon {
        return Ok(0);
    }
    Ok(tamper(TAMPER_KILL, sig, core::ptr::null()))
}

/// `ptrace_access_check(child, mode)`: no ptrace-level access (attach,
/// /proc/PID/mem, process_vm_writev, pidfd_getfd) to the daemon, nor to init,
/// which holds the daemon's map fds in its fd store. Read-only /proc access
/// (PTRACE_MODE_READ) stays allowed.
#[lsm(hook = "ptrace_access_check")]
pub fn ptrace_access_check(ctx: LsmContext) -> i32 {
    let prev: i32 = ctx.arg(2);
    if prev != 0 {
        return prev;
    }
    guarded(unsafe { try_ptrace(&ctx) })
}

#[inline(always)]
unsafe fn try_ptrace(ctx: &LsmContext) -> R<i32> {
    let mode: u64 = ctx.arg::<u64>(1) & 0xffff_ffff;
    if mode & PTRACE_MODE_ATTACH == 0 {
        return Ok(0);
    }
    let child: *const u8 = ctx.arg(0);
    let target: u32 = read(child, off(&OFF_TASK_TGID))?;
    let daemon = ctl(CTL_DAEMON_TGID);
    if target != 1 && (daemon == 0 || target != daemon) {
        return Ok(0);
    }
    if current_tgid() == target {
        return Ok(0);
    }
    Ok(tamper(TAMPER_PTRACE, target as u64, core::ptr::null()))
}

/// Refuses writes to `kernel.ftrace_enabled`: setting it to 0 stops all ftrace
/// callsites, including the BPF trampolines that run the LSM programs, which
/// would disarm them silently. cgroup/sysctl programs run from the sysctl
/// handler, not through ftrace. Attached to the root cgroup: covers all
/// tasks; programs further down can't override it.
///
/// Return value: 1 allows the access, 0 refuses it with -EPERM.
#[cgroup_sysctl]
pub fn sysctl_guard(ctx: SysctlContext) -> i32 {
    if unsafe { (*ctx.sysctl).write } == 0 {
        return 1;
    }
    // Full name relative to /proc/sys, NUL-terminated; the rest stays zero.
    let mut name = [0u64; 3];
    let len = unsafe { bpf_sysctl_get_name(ctx.sysctl, name.as_mut_ptr().cast(), 24, 0) };
    // Compared as words: a byte loop or slice compare can turn into a
    // memcmp call, which BPF doesn't have.
    const WANT: [u64; 3] = [
        u64::from_ne_bytes(*b"kernel/f"),
        u64::from_ne_bytes(*b"trace_en"),
        u64::from_ne_bytes(*b"abled\0\0\0"),
    ];
    if len != 21 || name[0] != WANT[0] || name[1] != WANT[1] || name[2] != WANT[2] {
        return 1;
    }
    unsafe { tamper(TAMPER_SYSCTL, 0, core::ptr::null()) };
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[no_mangle]
static LICENSE: [u8; 4] = *b"GPL\0";
