//! snitch's BPF LSM programs (monitor mode): report changes to watched files
//! and to entries of watched directories.
//!
//! Watched inodes are keyed by (kernel dev_t, inode number) in `WATCHED`,
//! filled by the loader from the hash database. Events go to `EVENTS`.
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
    },
    macros::{lsm, map},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::LsmContext,
};
use snitch_ebpf_common::{
    Event, InodeKey, EV_CHMOD, EV_CHOWN, EV_CLOSE_WRITE, EV_CREATE, EV_INODE_FREED, EV_LINK,
    EV_OPEN_WRITE, EV_RENAME_FROM, EV_RENAME_OVER, EV_TRUNCATE, EV_UNLINK, NAME_LEN, STAT_DROPPED,
    STAT_EVENTS, STAT_LEN, STAT_READ_ERRORS, WATCH_DIR, WATCH_FILE,
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

/// Resized by the loader to fit the database.
#[map]
static WATCHED: HashMap<InodeKey, u32> = HashMap::with_max_entries(1024, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(STAT_LEN, 0);

const FMODE_WRITE: u32 = 0x2;

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
    verdict(unsafe { try_path_unlink(&ctx) })
}

#[inline(always)]
unsafe fn try_path_unlink(ctx: &LsmContext) -> R<()> {
    let dentry: *const u8 = ctx.arg(1);
    if let Some(key) = watched_dentry(dentry, WATCH_FILE)? {
        emit(EV_UNLINK, key, dentry);
    }
    Ok(())
}

#[lsm(hook = "path_rename")]
pub fn path_rename(ctx: LsmContext) -> i32 {
    let prev: i32 = ctx.arg(5);
    if prev != 0 {
        return prev;
    }
    verdict(unsafe { try_path_rename(&ctx) })
}

#[inline(always)]
unsafe fn try_path_rename(ctx: &LsmContext) -> R<()> {
    let old_dentry: *const u8 = ctx.arg(1);
    let new_dir: *const u8 = ctx.arg(2);
    let new_dentry: *const u8 = ctx.arg(3);
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
    Ok(())
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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[no_mangle]
static LICENSE: [u8; 4] = *b"GPL\0";
