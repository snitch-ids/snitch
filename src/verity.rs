//! dm-verity: file systems the kernel checks block by block against a hash
//! tree whose root hash was fixed when the image was built. Their files can't
//! change: a modified block is a read error. So snitch doesn't hash them. It
//! reports the root hashes with the heartbeats instead, and the backend alerts
//! when they change ("Image changed").
//!
//! Files are matched by their device (`st_dev`): whatever is mounted over a
//! verified path is hashed and watched as usual. Without dm-verity nothing
//! changes: snitch hashes and watches everything (standalone).

use std::collections::HashSet;
use std::fs::Metadata;
use std::path::{Path, PathBuf};

use serde::Serialize;

/// A mounted dm-verity file system, as the heartbeats report it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VerityMount {
    /// Where it is mounted (the first of its mount points that overlaps the
    /// watched directories).
    pub mount: String,
    /// Root hash of the hash tree (hex).
    pub root_hash: String,
    /// The kernel checked a signature of the root hash when the device was
    /// set up (`root_hash_sig_key_desc`).
    pub signed: bool,
    /// The kernel found a block that doesn't match the hash tree.
    pub corrupted: bool,
}

/// The dm-verity file systems that overlap the watched directories.
#[derive(Debug, Default)]
pub struct Verity {
    /// `st_dev` of the verified devices
    devices: HashSet<u64>,
    /// Mount points of all other file systems
    others: Vec<PathBuf>,
    pub mounts: Vec<VerityMount>,
    /// dm-verity devices that don't count, and why.
    pub ignored: Vec<String>,
    /// Why the detection couldn't look at every device-mapper device.
    pub error: Option<String>,
}

impl Verity {
    /// Find the dm-verity file systems that overlap `dirs`. Reading
    /// device-mapper tables needs root; see [`Verity::error`].
    pub fn detect(dirs: &[&Path]) -> Verity {
        #[cfg(target_os = "linux")]
        return linux::detect(dirs);
        #[cfg(not(target_os = "linux"))]
        {
            let _ = dirs;
            Verity::default()
        }
    }

    /// No verified file systems: everything is hashed and watched.
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// Whether the file with this metadata is on a verified file system.
    #[cfg(unix)]
    pub fn verified(&self, md: &Metadata) -> bool {
        use std::os::unix::fs::MetadataExt;
        !self.devices.is_empty() && self.devices.contains(&md.dev())
    }

    #[cfg(not(unix))]
    pub fn verified(&self, _md: &Metadata) -> bool {
        false
    }

    /// Whether `path` (not following a final symlink) is on a verified file
    /// system.
    pub fn verified_path(&self, path: &Path) -> bool {
        !self.devices.is_empty()
            && std::fs::symlink_metadata(path).is_ok_and(|md| self.verified(&md))
    }

    /// Where to walk or watch for `dirs`: a directory on a verified file
    /// system is replaced by the other file systems mounted below it, and so
    /// is any verified file system mounted below a directory. Walks have to
    /// leave out verified directories ([`Verity::verified`]); then every file
    /// that isn't verified is reached exactly once.
    pub fn roots(&self, dirs: &[&Path]) -> Vec<PathBuf> {
        let mut roots: Vec<PathBuf> = Vec::new();
        for dir in dirs {
            if !self.verified_path(dir) {
                roots.push(dir.to_path_buf());
            }
            if self.devices.is_empty() {
                continue;
            }
            for mount in &self.others {
                let below_verified = mount
                    .ancestors()
                    .skip(1)
                    .take_while(|a| a.starts_with(dir))
                    .any(|a| self.verified_path(a));
                // Skip mounts hidden by a mount over them (another device).
                if mount != dir
                    && mount.starts_with(dir)
                    && below_verified
                    && !self.verified_path(mount)
                    && !roots.contains(mount)
                {
                    roots.push(mount.clone());
                }
            }
        }
        roots
    }

    /// One line per verified file system, for logs.
    pub fn describe(&self) -> Vec<String> {
        self.mounts
            .iter()
            .map(|m| {
                format!(
                    "{} is dm-verity (root hash {}{}{})",
                    m.mount,
                    short(&m.root_hash),
                    if m.signed { ", signed" } else { "" },
                    if m.corrupted {
                        ", CORRUPTED blocks found"
                    } else {
                        ""
                    }
                )
            })
            .collect()
    }
}

/// The first 16 hex digits.
pub fn short(hash: &str) -> &str {
    &hash[..hash.len().min(16)]
}

/// What a dm-verity table says (`STATUSTYPE_TABLE`):
/// `<version> <data dev> <hash dev> <data block size> <hash block size>
/// <data blocks> <hash start> <algorithm> <root hash> <salt> [<n> <options>...]`
#[derive(Debug, PartialEq)]
struct Table {
    root_hash: String,
    signed: bool,
    /// `ignore_corruption`: bad blocks are only logged, and read anyway.
    ignores_corruption: bool,
}

fn parse_table(params: &str) -> Option<Table> {
    let words: Vec<&str> = params.split_whitespace().collect();
    let root_hash = *words.get(8)?;
    if root_hash.is_empty() || !root_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let options = words.get(10..).unwrap_or_default();
    Some(Table {
        root_hash: root_hash.to_ascii_lowercase(),
        signed: options.contains(&"root_hash_sig_key_desc"),
        ignores_corruption: options.contains(&"ignore_corruption"),
    })
}

/// A line of `/proc/self/mountinfo`: device and mount point.
#[derive(Debug, PartialEq)]
struct Mount {
    major: u32,
    minor: u32,
    mount_point: PathBuf,
}

fn parse_mountinfo(text: &str) -> Vec<Mount> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split(' ');
            let (major, minor) = fields.nth(2)?.split_once(':')?;
            let mount_point = unescape(fields.nth(1)?);
            Some(Mount {
                major: major.parse().ok()?,
                minor: minor.parse().ok()?,
                mount_point: PathBuf::from(mount_point),
            })
        })
        .collect()
}

/// mountinfo escapes space, tab, newline and backslash as `\ooo`.
fn unescape(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let octal = bytes.get(i + 1..i + 4).filter(|d| {
            bytes[i] == b'\\'
                && (b'0'..=b'3').contains(&d[0])
                && d[1..].iter().all(|b| (b'0'..=b'7').contains(b))
        });
        match octal {
            Some(d) => {
                out.push((d[0] - b'0') << 6 | (d[1] - b'0') << 3 | (d[2] - b'0'));
                i += 4;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::fs::File;
    use std::io;
    use std::os::fd::AsRawFd;

    pub(super) fn detect(dirs: &[&Path]) -> Verity {
        let mut verity = Verity::default();
        let mounts = match std::fs::read_to_string("/proc/self/mountinfo") {
            Ok(text) => parse_mountinfo(&text),
            Err(err) => {
                verity.error = Some(format!("reading /proc/self/mountinfo: {err}"));
                return verity;
            }
        };
        let overlaps = |m: &Path| dirs.iter().any(|d| m.starts_with(d) || d.starts_with(m));
        let mut control: Option<File> = None;
        let mut seen = HashSet::new();
        for mount in &mounts {
            let (major, minor) = (mount.major, mount.minor);
            if !overlaps(&mount.mount_point) || !seen.insert((major, minor)) {
                continue;
            }
            if !Path::new(&format!("/sys/dev/block/{major}:{minor}/dm")).exists() {
                continue;
            }
            if control.is_none() {
                match File::options()
                    .read(true)
                    .write(true)
                    .open("/dev/mapper/control")
                {
                    Ok(file) => control = Some(file),
                    Err(err) => {
                        verity.error = Some(format!(
                            "can't read device-mapper tables: /dev/mapper/control: {err}{}",
                            if err.kind() == io::ErrorKind::PermissionDenied {
                                " (needs root)"
                            } else {
                                ""
                            }
                        ));
                        break;
                    }
                }
            }
            let control = control.as_ref().unwrap();
            let name = mount.mount_point.display().to_string();
            let table = match dm::targets(control, major, minor, true) {
                Ok(targets) => targets,
                Err(err) => {
                    verity.error = Some(format!("device-mapper table of {name}: {err}"));
                    continue;
                }
            };
            if table.is_empty() || table.iter().any(|t| t.kind != "verity") {
                continue;
            }
            let Some(parsed) = table
                .iter()
                .map(|t| parse_table(&t.params))
                .collect::<Option<Vec<_>>>()
            else {
                verity
                    .ignored
                    .push(format!("{name}: can't read its dm-verity table"));
                continue;
            };
            if parsed.iter().any(|t| t.ignores_corruption) {
                verity.ignored.push(format!(
                    "{name}: dm-verity with ignore_corruption only logs bad blocks and reads \
                     them anyway"
                ));
                continue;
            }
            let corrupted = dm::targets(control, major, minor, false)
                .map(|status| status.iter().any(|t| t.params.starts_with('C')))
                .unwrap_or(false);
            verity.devices.insert(libc::makedev(major, minor));
            verity.mounts.push(VerityMount {
                mount: name,
                root_hash: parsed[0].root_hash.clone(),
                signed: parsed.iter().all(|t| t.signed),
                corrupted,
            });
        }
        for mount in mounts {
            let dev = libc::makedev(mount.major, mount.minor);
            if !verity.devices.contains(&dev) && !verity.others.contains(&mount.mount_point) {
                verity.others.push(mount.mount_point);
            }
        }
        verity
    }

    /// The device-mapper ioctl interface (`linux/dm-ioctl.h`), for
    /// `DM_TABLE_STATUS`: what `dmsetup table` and `dmsetup status` show.
    mod dm {
        use super::*;

        /// `_IOWR(0xfd, DM_TABLE_STATUS_CMD = 12, struct dm_ioctl)`
        const DM_TABLE_STATUS: libc::c_ulong = 0xc138_fd0c;
        const DM_STATUS_TABLE_FLAG: u32 = 1 << 4;
        const DM_BUFFER_FULL_FLAG: u32 = 1 << 8;
        /// `sizeof(struct dm_ioctl)`, which is also where the data starts
        const HEADER: usize = 312;
        /// `sizeof(struct dm_target_spec)`
        const SPEC: usize = 40;

        pub struct Target {
            pub kind: String,
            pub params: String,
        }

        /// The targets of device `major:minor`, with their table lines
        /// (`table`) or their status lines.
        pub fn targets(
            control: &File,
            major: u32,
            minor: u32,
            table: bool,
        ) -> io::Result<Vec<Target>> {
            let mut size = 16 * 1024;
            loop {
                // u64 words: struct dm_ioctl has a u64 member.
                let mut words = vec![0u64; size / 8];
                let buf =
                    unsafe { std::slice::from_raw_parts_mut(words.as_mut_ptr() as *mut u8, size) };
                put_u32(buf, 0, 4); // version 4.0.0
                put_u32(buf, 12, size as u32); // data_size
                put_u32(buf, 16, HEADER as u32); // data_start
                put_u32(buf, 28, if table { DM_STATUS_TABLE_FLAG } else { 0 });
                // dev: huge_encode_dev(), as the kernel decodes it
                let dev =
                    (minor as u64 & 0xff) | ((major as u64) << 8) | ((minor as u64 & !0xff) << 12);
                buf[40..48].copy_from_slice(&dev.to_ne_bytes());
                let ret = unsafe {
                    libc::ioctl(control.as_raw_fd(), DM_TABLE_STATUS as _, buf.as_mut_ptr())
                };
                if ret < 0 {
                    return Err(io::Error::last_os_error());
                }
                if get_u32(buf, 28) & DM_BUFFER_FULL_FLAG != 0 {
                    if size >= 1 << 20 {
                        return Err(io::Error::other("device-mapper table too large"));
                    }
                    size *= 4;
                    continue;
                }
                return Ok(parse_targets(buf));
            }
        }

        fn parse_targets(buf: &[u8]) -> Vec<Target> {
            let count = get_u32(buf, 20) as usize;
            let start = get_u32(buf, 16) as usize;
            let end = (get_u32(buf, 12) as usize).min(buf.len());
            let mut targets = Vec::new();
            let mut pos = start;
            for _ in 0..count {
                if pos + SPEC > end {
                    break;
                }
                let spec = &buf[pos..pos + SPEC];
                let kind = c_str(&spec[24..40]);
                let params = c_str(&buf[pos + SPEC..end]);
                targets.push(Target { kind, params });
                let next = get_u32(spec, 20) as usize;
                if next == 0 {
                    break;
                }
                pos = start + next;
            }
            targets
        }

        fn c_str(bytes: &[u8]) -> String {
            let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            String::from_utf8_lossy(&bytes[..len]).into_owned()
        }

        fn put_u32(buf: &mut [u8], off: usize, v: u32) {
            buf[off..off + 4].copy_from_slice(&v.to_ne_bytes());
        }

        fn get_u32(buf: &[u8], off: usize) -> u32 {
            u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mountinfo() {
        let text = "\
22 1 252:0 / / ro,relatime shared:1 - ext4 /dev/mapper/root ro
23 22 0:21 / /proc rw shared:12 - proc proc rw
30 22 8:3 / /mnt/with\\040space rw - ext4 /dev/sda3 rw
";
        let mounts = parse_mountinfo(text);
        assert_eq!(mounts.len(), 3);
        assert_eq!((mounts[0].major, mounts[0].minor), (252, 0));
        assert_eq!(mounts[0].mount_point, Path::new("/"));
        assert_eq!(mounts[2].mount_point, Path::new("/mnt/with space"));
    }

    #[test]
    fn verity_table() {
        let hash = "4392712ba01368efdf14b05c76f9e4df0d53664630b5d48632ed17a137f39076";
        let plain = format!(
            "1 8:17 8:18 4096 4096 262144 1 sha256 {hash} 1234000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(
            parse_table(&plain),
            Some(Table {
                root_hash: hash.into(),
                signed: false,
                ignores_corruption: false
            })
        );
        let signed = format!(
            "1 7:0 7:1 4096 4096 2560 1 sha256 {hash} - 3 restart_on_corruption root_hash_sig_key_desc keyring:verity"
        );
        assert!(parse_table(&signed).unwrap().signed);
        let logging = format!("1 7:0 7:1 4096 4096 2560 1 sha256 {hash} - 1 ignore_corruption");
        assert!(parse_table(&logging).unwrap().ignores_corruption);
        assert_eq!(parse_table("0 0 0 linear"), None);
    }

    #[test]
    fn roots_without_verity() {
        let verity = Verity::default();
        let dirs = [Path::new("/etc"), Path::new("/usr")];
        assert_eq!(
            verity.roots(&dirs),
            vec![PathBuf::from("/etc"), PathBuf::from("/usr")]
        );
    }
}
