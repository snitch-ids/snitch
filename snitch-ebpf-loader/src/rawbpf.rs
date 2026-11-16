//! The two bpf() commands aya 0.14 doesn't expose for cgroup programs:
//! creating a link whose fd we own, and pinning it. (aya keeps the fd of a
//! cgroup link private and has no `FdLink` conversion for it.)

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

// enum bpf_cmd
const BPF_OBJ_PIN: libc::c_long = 6;
const BPF_LINK_CREATE: libc::c_long = 28;
// enum bpf_attach_type
pub const BPF_CGROUP_SYSCTL: u32 = 18;

/// Leading fields of `union bpf_attr` for BPF_LINK_CREATE. The kernel zeroes
/// the part of the union we don't pass.
#[repr(C)]
struct LinkCreateAttr {
    prog_fd: u32,
    target_fd: u32,
    attach_type: u32,
    flags: u32,
}

/// Leading fields of `union bpf_attr` for BPF_OBJ_PIN.
#[repr(C)]
struct ObjPinAttr {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}

fn sys_bpf<T>(cmd: libc::c_long, attr: &mut T) -> io::Result<libc::c_long> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd,
            attr as *mut T,
            std::mem::size_of::<T>() as libc::c_uint,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

pub fn link_create(
    prog: BorrowedFd<'_>,
    target: BorrowedFd<'_>,
    attach_type: u32,
    flags: u32,
) -> io::Result<OwnedFd> {
    let mut attr = LinkCreateAttr {
        prog_fd: prog.as_raw_fd() as u32,
        target_fd: target.as_raw_fd() as u32,
        attach_type,
        flags,
    };
    let fd = sys_bpf(BPF_LINK_CREATE, &mut attr)?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

pub fn obj_pin(fd: BorrowedFd<'_>, path: &Path) -> io::Result<()> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut attr = ObjPinAttr {
        pathname: path.as_ptr() as u64,
        bpf_fd: fd.as_raw_fd() as u32,
        file_flags: 0,
    };
    sys_bpf(BPF_OBJ_PIN, &mut attr)?;
    Ok(())
}
