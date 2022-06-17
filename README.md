Snitch - Intrusion Notification
===============================

[![Rust](https://github.com/HerrMuellerluedenscheid/snitch/actions/workflows/rust.yml/badge.svg)](https://github.com/HerrMuellerluedenscheid/snitch/actions/workflows/rust.yml)

Snitch is a file integrity and authentication monitoring system.

 * Snitch calculates and stores hashes of files found by recursing user defined directory trees. If a file hash changes Snitch will send a warning to the user (via email or telegram) to notify about the modified file.

 * Snitch also watches authentication logs and sends a notification when user logs in.

Requirements
------------

This is work in progress that requires `rust nightly` features:

```
rustup default nightly
```

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

To start watching authentication logs use:
```
snitch --watch
```

Configuration
-------------

Snitch can be configured in `etc/snitch/config.yaml`. If that file does not exist you can run

```
snitch --demo-config > /etc/snitch/config.yaml
```
to create a template that should be fine on `Ubuntu` and `Debian`.

All files found under `directories` in that file will be integrity checked. 

## Notification Channels

### Telegram

   Requires environment variables: `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`.

### Slack

   Requires environment variables: `SLACK_WEBHOOK_URL` and `SLACK_CHANNEL`.

### Email

   Requires environment variables: `SMTP_SERVER`, `SMTP_USER` and `SMTP_PASSWORD`. Note, that storing email credentials on your system in clear text is a rather high risk once someone gained access. Thus, this should rather be used for development for now.

Performance
-----------

`Ubuntu20.04` (~150.000 files) takes about one minute to hash on one virtual CPU using `SHA265` hashing.
