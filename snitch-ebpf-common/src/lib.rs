//! Types shared between snitch's BPF programs (`snitch-ebpf`) and the
//! userspace loader (`snitch --watch-ebpf`).
#![no_std]

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
pub const STAT_LEN: u32 = 3;

#[cfg(feature = "user")]
unsafe impl aya::Pod for InodeKey {}
