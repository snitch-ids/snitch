Nitro - Intrusion Notification
==============================

[![Rust](https://github.com/HerrMuellerluedenscheid/nitro/actions/workflows/rust.yml/badge.svg)](https://github.com/HerrMuellerluedenscheid/nitro/actions/workflows/rust.yml)

Nitro is a file integrity and authentication monitoring system.

 * Nitro calculates and stores hashes of files found by recursing user defined directory trees. If a file hash changes Nitro will send a warning to the user (via email or telegram) to notify about the modified file.

 * Nitro also watches authentication logs and sends a notification when user logs in.

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
cargo install --path .
```

Usage
-----

Run the initial scan
```
nitro --init
```

and trigger a scan to verify file integrity with
```
nitro --scan
```

To start watching authentication logs use:
```
nitro --watch
```

Configuration
-------------

Nitro can be configured in `etc/nitro/config.yaml`. If that file does not exist you can run

```
nitro --demo-config > /etc/nitro/config.yaml
```
to create a template that should be fine on `Ubuntu` and `Debian`.

All files found under `directories` in that file will be integrity checked. 

## Notification Channels

### Telegram

   Requires environment variables: `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`.

### Email

   Requires environment variables: `SMTP_SERVER`, `SMTP_USER` and `SMTP_PASSWORD`. Note, that storing email credentials on your system in clear text is a rather high risk once someone gained access. Thus, this should rather be used for development for now.

Performance
-----------

`Ubuntu20.04` (~150.000 files) takes about one minute to hash on one virtual CPU using `SHA265` hashing.
