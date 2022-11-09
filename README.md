Snitch - Intrusion Notification
===============================

[![Rust](https://github.com/HerrMuellerluedenscheid/snitch/actions/workflows/rust.yml/badge.svg)](https://github.com/HerrMuellerluedenscheid/snitch/actions/workflows/rust.yml)

Snitch is a file integrity and authentication monitoring system.

 * Snitch calculates and stores hashes of files found by recursing user defined directory trees. If a file hash changes Snitch will send a warning to the user (via email or telegram) to notify about the modified file.

 * Snitch also watches authentication logs and sends a notification when user logs in.

Requirements
------------

First, make sure that you have the [rust compiler](https://www.rust-lang.org/tools/install) installed.

On a plain Ubuntu/Debian you also need to:

```
apt install gcc build-essential pkg-config libssl-dev
```

Installation
------------

```
cargo install snitch
```

Note that access to root level folders and monitoring authentication logs usually requires an installation as `root`.

Usage
-----

Run the initial scan
```
snitch --init
```

and trigger a scan to verify file integrity with
```
snitch --scan
```

Watch authentication logs:
```
snitch --watch-authentications
```

Watch for file changes:
```
snitch --watch-files
```

Configuration
-------------

Snitch can be configured in `/etc/snitch/config.yaml`. If that file does not exist you can run

```
snitch --demo-config > /etc/snitch/config.yaml
```
to create a template that should be fine on **Linux**, **OSX** and **Windows**.

This is on example configuration:

```
---
directories:
  - /System
  - /Users
  - /sbin
  - /opt
sender:
  telegram:
    bot_token: 3892394878927:DLKjsjs-EXAMPLE-exampleJDij4s
    chat_id: 1234567890
  email:
    smtp_user: secure
    smtp_password: secure
    smtp_server: example-server.org
    receiver_address: my-receiving-address@gmail.com
  slack:
    webhook_url: sendmymessagestoslack.com
    channel: #mysecuritymessages
authentication_logs: ~
snitch_root: /etc/snitch
```

Each `sender` is optional. More to follow... 

Performance
-----------

`Ubuntu20.04` (~150.000 files) takes about one minute to hash on one virtual CPU using `SHA265` hashing.
