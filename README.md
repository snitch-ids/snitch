Snitch - Intrusion Detection System
===================================

[![Rust](https://github.com/HerrMuellerluedenscheid/snitch/actions/workflows/rust.yml/badge.svg)](https://github.com/HerrMuellerluedenscheid/snitch/actions/workflows/rust.yml)

Snitch is a file integrity and authentication monitoring system.

 * Snitch calculates and persists hashes of files found by recursing user defined `directories`. If a file hash changes Snitch will send a warning to the user via a `sender` to notify about the modified file.

 * Snitch can also watch authentication logs and send a notification when user logs in or become root.

Installation
------------

## Pre-compiled

Get the `deb` package or precompiled binary for OSX from the [latest release](https://github.com/HerrMuellerluedenscheid/snitch/releases).

## Homebrew

```shell
brew tap snitch-ids/snitch
brew install snitch
```

## From source

```
cargo install snitch
```

Note that access to root level folders and monitoring authentication logs usually requires an installation as `root`.

## Linux distributions (systemd)

On Debian, Ubuntu, Fedora and other distributions with systemd, as root:

1. Build snitch with BPF support (see "Watch files with BPF LSM programs"
   below), install it, and create the configuration (see Configuration):
   ```
   install -m 755 target/release/snitch /usr/bin/
   install -m 755 target/release/snitch-ebpf-load /usr/sbin/
   mkdir -p /etc/snitch
   snitch --demo-config > /etc/snitch/config.yaml
   ```
2. See what works on this machine and what's missing:
   ```
   snitch --check
   ```
   It prints the fix for each problem, for example the `lsm=` kernel
   parameter when the kernel has the BPF LSM but doesn't use it (Ubuntu).
3. Start snitch now and at every boot:
   ```
   install -m 644 extra/systemd/snitch.service extra/systemd/snitch-init.service /etc/systemd/system/
   systemctl daemon-reload
   systemctl enable --now snitch.service
   ```
   The first start hashes the watched files (`snitch-init.service`).
   `snitch --watch` then uses BPF LSM programs if the kernel has them,
   otherwise inotify.
4. Optionally, load the BPF programs at boot, so that root can't stop
   snitch (see "Protection at boot").

Tested with Ubuntu 24.04 (Linux 6.8) and Yocto (Linux 6.18). The BPF LSM
programs need a kernel with BTF and the BPF LSM; where something is
missing, `snitch --check` says what, and `snitch --watch` uses inotify.

Configuration
-------------

Snitch can be configured in `/etc/snitch/config.yaml`. If that file does not exist you can run

```
snitch --demo-config > /etc/snitch/config.yaml
```
to create a template that should be fine on **Linux**, **OSX** and **Windows** to get started.

This is on example configuration:

```
---
directories:
  - /System
  - /Users
  - /sbin
  - /opt
sender:
  backend:
    url: https://api.snitch.cool
    token: MYPERSONALGENERATEDTOKEN
  telegram:
    bot_token: 3892394878927:DLKjsjs-EXAMPLE-exampleJDij4s
    chat_id: 1234567890
  email:
    smtp_user: secure
    smtp_password: secure
    smtp_server: imap.foo.bar
    receiver_address: my-receiving-address@gmail.com
  slack:
    webhook_url: sendmymessagestoslack.com
    channel: #mysecuritymessages
authentication_logs: ~
snitch_root: /tmp/snitch/
```

Each `sender` is optional. Set `token: ""` to not send messages to the
[snitch.cool](http://snitch.cool) backend; they are still logged.

## Connect to [snitch.cool](http://snitch.cool)

Go to [snitch.cool](http://snitch.cool) and `register` with your email and a password.
Confirm the email address. Go to `Token` and click `Create Token`.

Copy the created token and paste it into the section in your snitch `config.yaml`:
```yaml
sender:
  backend:
    url: https://api.snitch.cool
    token: <PASTE-TOKEN-HERE>
```

Usage
-----

See what works on this machine and what's missing, with the fix for each
(kernel support, protection at boot, configuration, database, backend):
```
snitch --check
```

Test the configured senders:
```
snitch --send-test-message
```

Run the initial scan
```
snitch --init
```

and trigger a scan to verify file integrity with
```
snitch --scan
```

Watch for file changes, the best way this machine supports (like
`--watch-ebpf` if the kernel has the BPF LSM active, otherwise like
`--watch-files`):
```
snitch --watch
```

Watch for file changes with inotify:
```
snitch --watch-files
```

Watch authentication logs:
```
snitch --watch-authentications
```

Watch files with BPF LSM programs (Linux, experimental):
```
snitch --watch-ebpf
```
This reports, with the process that did it: writes to files from the
database (re-hashed when the writer closes the file, reported on mismatch),
removal, renames and replacement, new hard links, permission and owner
changes, and new entries in the configured directories. It needs root, a
kernel with `CONFIG_BPF_LSM` and BTF, `bpf` in the active LSMs
(`cat /sys/kernel/security/lsm`), and a build with the `ebpf` feature:
```
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
cargo build --release --features ebpf
cargo build --release -p snitch-ebpf-loader   # snitch-ebpf-load, for protection at boot
```
`snitch-ebpf-loader/build.rs` builds the BPF programs in `snitch-ebpf/` with
nightly. To use a prebuilt object instead (e.g. in Yocto), set
`SNITCH_BPF_OBJ=<path>`.

Started like this, snitch loads the programs itself, and they stay attached
while it runs. Root can still stop snitch. To prevent that, load them at
boot (see "Protection at boot").

`--watch-ebpf` compares every file with the database when it starts, and
reports the ones that changed or disappeared while it wasn't watching. Each
start reports them again until you accept the change:
```
snitch --accept /etc/issue
```

To build the database for an image, hash its root file system as if it were
`/`. The database goes below it too:
```
snitch --init --root /path/to/rootfs --config /path/to/rootfs/etc/snitch/config.yaml
```

`--watch-ebpf` tests itself every minute. It writes a canary file
(`/run/snitch/canary`) and expects the BPF programs to report it. With the
programs loaded at boot, it also checks that removing a protected pin is
refused. A failure is reported as "Self-test failed". This covers the
programs being detached or disarmed in ways the protection doesn't know about.

Protection at boot
------------------

`snitch-ebpf-load` (in `snitch-ebpf-loader/`) loads the BPF programs from
the initramfs, after the root file system is mounted and before the system
switches to it:
```
snitch-ebpf-load --root /sysroot
```
It attaches the monitoring programs plus self-protection, and pins them in
`/sys/fs/bpf/snitch` (mounting bpffs there if needed). Then snitch claims
the pinned maps. From then on, even root can't:
- open them, or detach or unpin the programs
- unmount bpffs, `/sys` or `/`
- write `kernel.ftrace_enabled` (which would disarm the programs)
- kill or ptrace snitch, or ptrace init

Refused attempts are reported as "Tamper attempt blocked". snitch keeps the
map fds in systemd's fd store (`extra/systemd/snitch.service`) and gets
them back from there after a restart.

systemd hands those fds to whatever `snitch.service` starts. The exec lock
keeps a unit drop-in from running anything else there:
- only snitch and systemd-executor (as found at boot) may run in the unit
  (`--trusted-exe` to name others)
- nobody may open them for writing
- once snitch has claimed its maps, executable mappings in the unit must
  come from files in the hash database (no `LD_PRELOAD` from `/tmp`)

To set it up:
- Debian, Ubuntu (initramfs-tools):
  ```
  install -m 755 extra/initramfs-tools/hooks/snitch /etc/initramfs-tools/hooks/
  install -m 755 extra/initramfs-tools/scripts/init-bottom/snitch /etc/initramfs-tools/scripts/init-bottom/
  update-initramfs -u
  ```
  Ubuntu cloud images first try to boot without an initramfs, so the hook
  never runs. Turn that off, then update GRUB:
  ```
  rm /etc/default/grub.d/40-force-partuuid.cfg
  update-grub
  ```
- Fedora, RHEL and others with dracut:
  ```
  mkdir -p /usr/lib/dracut/modules.d/95snitch
  install -m 755 extra/dracut/95snitch/* /usr/lib/dracut/modules.d/95snitch/
  dracut -f
  ```
- Yocto: the layer meta-snitch bundles an initramfs with the loader into
  the kernel.

After a reboot, `snitch --check` shows "BPF programs loaded at boot". Also
boot with `lockdown=integrity`: otherwise root can load unsigned kernel
modules and get around the protection. Most distributions build the
initramfs on the device and don't sign it, so root can build one without
the loader and reboot. The heartbeat then reports the reboot and the
changed mode. A signed boot chain (e.g. a signed UKI) closes that.

Updating snitch: install the new binaries (and the initramfs, e.g.
`update-initramfs -u`), then reboot. The exec lock trusts the binary it
found at boot, so until the reboot `snitch.service` can't start the new one.
If it isn't restarted, the running snitch keeps watching.

dm-verity
---------

If a watched directory is on a dm-verity file system (a verified root, or a
verified `/usr` as with systemd's `usrhash=`), snitch uses it; nothing to
configure. dm-verity is never required.

- Files there aren't hashed (`--init`, the startup check, `--scan`): the
  kernel checks every block against the image's hash tree, so they can't
  change. In BPF mode they stay in the watch map, so the exec lock trusts
  snitch's own libraries on a verified `/usr`.
- What is mounted below or over a verified path (a writable `/var`, an
  overlay on `/etc`, a tmpfs) is hashed and watched as usual.
- Heartbeats carry the root hash of each verified file system. The backend
  alerts "Image changed" when a new session reports other root hashes, or
  none: another image was booted.
- `snitch --check` lists them, and fails if dm-verity found corrupted blocks.
  A device set up with `ignore_corruption` (logs bad blocks but returns
  them) doesn't count as verified.

snitch reads the device-mapper tables (as `dmsetup table` does), which
needs root.

Heartbeats
----------

With a backend token, `--watch` sends a heartbeat every
`heartbeat_interval` seconds (config, default 60; 0 turns them off). The
heartbeat carries the boot id, the monitoring mode, the self-test result,
the number of watched files, the path and SHA-256 of the configuration
file, and the dm-verity root hashes. The backend alerts when:
- heartbeats stop, and when they come back
- snitch restarts, or the host reboots
- snitch restarts with another configuration file
- snitch restarts on another dm-verity image
- a heartbeat is forged or replayed

Each snitch process signs its heartbeats with a random key of its own
(HMAC-SHA256) and numbers them. Whoever stops snitch can't keep its
heartbeats going: another sender is another session, which the backend
reports as a restart.

Performance
-----------

`Ubuntu20.04` (~150.000 files) takes about one minute to hash on one virtual CPU core using `SHA265` hashing.
