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

Watch for file changes:
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
```
`snitch-ebpf-loader/build.rs` builds the BPF programs in `snitch-ebpf/` with
nightly. To use a prebuilt object instead (e.g. in Yocto), set
`SNITCH_BPF_OBJ=<path>`.

Started like this, snitch loads the programs itself, and they stay attached
while it runs. On a device, load them at boot instead, from an initramfs
bundled into the kernel (the Yocto layer meta-snitch does this):
```
snitch-ebpf-load --root /rootfs --cgroup /sys/fs/cgroup
```
`snitch-ebpf-load` (in `snitch-ebpf-loader/`) attaches the monitoring
programs plus self-protection, and pins them in `/sys/fs/bpf/snitch`. Then
`snitch --watch-ebpf` claims the pinned maps; from then on, even root can't
open them, detach or unpin the programs, unmount bpffs, `/sys` or `/`, write
`kernel.ftrace_enabled` (which would disarm them), kill or ptrace snitch, or
ptrace init. Refused attempts are reported as "Tamper attempt blocked". Run
it as a systemd `Type=notify` service with `FileDescriptorStoreMax=8` and
`FileDescriptorStorePreserve=yes`: snitch keeps the map fds in systemd's fd
store and gets them back from there after a restart.

`--watch-ebpf` tests itself every minute. It writes a canary file
(`/run/snitch/canary`) and expects the BPF programs to report it. With the
programs loaded at boot, it also checks that removing a protected pin is
refused. A failure is reported as "Self-test failed". This covers the
programs being detached or disarmed in ways the protection doesn't know about.

Heartbeats
----------

With a backend token, `--watch-ebpf` and `--watch-files` send a heartbeat
every `heartbeat_interval` seconds (config, default 60; 0 turns them off).
The heartbeat carries the boot id, the monitoring mode and the self-test
result. The backend alerts when:
- heartbeats stop, and when they come back
- snitch restarts, or the host reboots
- a heartbeat is forged or replayed

Each snitch process signs its heartbeats with a random key of its own
(HMAC-SHA256) and numbers them. Whoever stops snitch can't keep its
heartbeats going: another sender is another session, which the backend
reports as a restart.

Performance
-----------

`Ubuntu20.04` (~150.000 files) takes about one minute to hash on one virtual CPU core using `SHA265` hashing.
