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

Each `sender` is optional.

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

Performance
-----------

`Ubuntu20.04` (~150.000 files) takes about one minute to hash on one virtual CPU core using `SHA265` hashing.
