//! Types shared between snitch's BPF programs (`snitch-ebpf`), the boot
//! loader (`snitch-ebpf-load`) and `snitch --watch-ebpf`.
#![no_std]

/// Bumped when maps, events or `CONTROL` change incompatibly. The boot loader
/// stores it in `CONTROL[CTL_ABI]`; `snitch --watch-ebpf` refuses pinned maps
/// from another version (e.g. a rootfs update without the matching kernel
/// image and its initramfs).
pub const ABI_VERSION: u32 = 1;

/// Key of the `WATCHED` map. `dev` is the kernel-internal `dev_t`
/// (`MAJOR << 20 | MINOR`), not the userspace `st_dev` encoding.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InodeKey {
    pub dev: u64,
    pub ino: u64,
}

/// `WATCHED` value: a file from the hash database
pub const WATCH_FILE: u32 = 1;
/// `WATCHED` value: a directory below one of the configured directories.
/// Changes to its entries (create, rename into, link into) are reported.
pub const WATCH_DIR: u32 = 2;

// Event kinds. `dev`/`ino` of the event is the watched inode; `name` is the
// other path component involved, where there is one.

/// A watched file was opened for writing.
pub const EV_OPEN_WRITE: u32 = 1;
/// A watched file that was open for writing was closed (last reference).
pub const EV_CLOSE_WRITE: u32 = 2;
/// A watched file was truncated by path (`truncate(2)`).
pub const EV_TRUNCATE: u32 = 3;
/// A watched file was unlinked. `name`: its name.
pub const EV_UNLINK: u32 = 4;
/// A watched file was renamed. `name`: the new name.
pub const EV_RENAME_FROM: u32 = 5;
/// A watched file was replaced by a rename onto its name. `name`: the name
/// of the file that replaces it.
pub const EV_RENAME_OVER: u32 = 6;
/// A watched file got another hard link. `name`: the new name.
pub const EV_LINK: u32 = 7;
/// An entry was created in a watched directory (file, directory, node,
/// symlink, hard link, or rename into it). `name`: the new entry.
pub const EV_CREATE: u32 = 8;
/// A watched file's or directory's mode was changed.
pub const EV_CHMOD: u32 = 9;
/// A watched file's or directory's owner was changed.
pub const EV_CHOWN: u32 = 10;
/// A watched inode was deleted (its last link is gone and it is freed). The
/// programs have already removed it from `WATCHED`, so a new file that gets
/// the same inode number is not mistaken for it.
pub const EV_INODE_FREED: u32 = 11;
/// An attempt to disable snitch was refused. `dev`: one of `TAMPER_*`;
/// `ino`: detail (bpf command, map id, signal, flags); `name`: the pin's
/// name for pin removal, the program for `TAMPER_EXEC`.
pub const EV_TAMPER: u32 = 12;

// What a refused tamper attempt tried to do (`Event::dev` of `EV_TAMPER`).

/// Write to `kernel.ftrace_enabled`, which would disarm all BPF LSM programs
pub const TAMPER_SYSCTL: u64 = 1;
/// `bpf()` command that detaches or replaces program links (`ino`: command)
pub const TAMPER_BPF_CMD: u64 = 2;
/// New fd for one of snitch's maps after the daemon claimed them (`ino`: map id)
pub const TAMPER_MAP_FD: u64 = 3;
/// Unlink of a pin in snitch's bpffs directory
pub const TAMPER_PIN_UNLINK: u64 = 4;
/// Rename of or onto a pin
pub const TAMPER_PIN_RENAME: u64 = 5;
/// Unmount of snitch's bpffs, sysfs or the root file system (`ino`: s_magic)
pub const TAMPER_UMOUNT: u64 = 6;
/// Moving a mount (`ino`: mount flags, 0 for move_mount(2))
pub const TAMPER_MOVE_MOUNT: u64 = 7;
/// pivot_root(2) in the initial mount namespace
pub const TAMPER_PIVOT_ROOT: u64 = 8;
/// Signal to the snitch daemon (`ino`: signal)
pub const TAMPER_KILL: u64 = 9;
/// ptrace-level access (attach, /proc/PID/mem, pidfd_getfd) to the daemon or
/// to init (`ino`: target tgid)
pub const TAMPER_PTRACE: u64 = 10;
/// A program other than the snitch binary found at boot executed in
/// snitch.service's cgroup, which would get snitch's map fds from systemd's
/// fd store (`name`: the program as passed to exec)
pub const TAMPER_EXEC: u64 = 11;
/// Opening the snitch binary found at boot for writing (`ino` 0), or
/// truncating it (`ino` 1). `name`: its name.
pub const TAMPER_EXE_WRITE: u64 = 12;
/// Executable mapping in snitch.service of a file that isn't in the hash
/// database (`LD_PRELOAD` and the like). `name`: the file's name.
pub const TAMPER_EXEC_MMAP: u64 = 13;

pub const NAME_LEN: usize = 64;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Event {
    pub kind: u32,
    /// Process (thread group) id
    pub tgid: u32,
    /// Thread id
    pub pid: u32,
    pub uid: u32,
    pub dev: u64,
    pub ino: u64,
    pub comm: [u8; 16],
    /// NUL-terminated, truncated to `NAME_LEN - 1` bytes
    pub name: [u8; NAME_LEN],
}

/// Indexes into the `STATS` per-CPU array.
pub const STAT_EVENTS: u32 = 0;
/// Events lost because the ring buffer was full
pub const STAT_DROPPED: u32 = 1;
/// Failed kernel memory reads (wrong offsets would show up here)
pub const STAT_READ_ERRORS: u32 = 2;
/// Refused tamper attempts
pub const STAT_DENIED: u32 = 3;
pub const STAT_LEN: u32 = 4;

/// Indexes into the `CONTROL` array.
///
/// `ABI_VERSION` of the loader that pinned the programs
pub const CTL_ABI: u32 = 0;
/// Non-zero once the daemon holds fds for all maps; from then on nobody gets
/// a new fd for them.
pub const CTL_LOCKED: u32 = 1;
/// tgid of the daemon (protected from signals and ptrace)
pub const CTL_DAEMON_TGID: u32 = 2;
/// Set by the programs when init (pid 1) executes a program from the root
/// file system, i.e. after switch_root. Mount moves and pivot_root are
/// refused from then on.
pub const CTL_ARMED: u32 = 3;
pub const CTL_LEN: u32 = 4;

#[cfg(feature = "user")]
unsafe impl aya::Pod for InodeKey {}
