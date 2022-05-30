Nitro - Intrusion Notification
==============================

[![Rust](https://github.com/HerrMuellerluedenscheid/nitro/actions/workflows/rust.yml/badge.svg)](https://github.com/HerrMuellerluedenscheid/nitro/actions/workflows/rust.yml)

Nitro is a file integrity and authentication monitoring system.

 * Nitro calculates and stores hashes of files found by recursing user defined directory trees. If a file hash changes Nitro will send a warning to the user (via email or telegram) to notify about the modified file.

 * Nitro also watches authentication logs and sends a notification when user logs in.

Requirements
------------

This is work in progress that requires `rust nightly` features. On a plain Ubuntu/Debian you also need to:

```
apt install gcc build-essential pkg-config libssl-dev
```

Installation
------------

```
cargo install --path .
```

Configuration
-------------

You can use
```
nitro --demo-config > /etc/nitro/config.yaml
```
to generate a configuration template to start with.

A minimalistic `/etc/nitro/config.yaml` example looks like:

```
---

# All directories listed here will be scanned:
directories:
  - /usr/local/bin
  - /home/myself/.bin
```

## Notification Channels

### Telegram

   Requires environment variables: `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`.

### Email

   Requires environment variables: `SMTP_SERVER`, `SMTP_USER` and `SMTP_PASSWORD`. Note, that storing email credentials on your system in clear text is a rather high risk once someone gained access. Thus, this should rather be used for development for now.

Usage
-----

Run the initial scan
```
nitro --init
```

and trigger a re-scan to verify file integrity with
```
nitro --scan
```

Performance
-----------

`Ubuntu20.04` (~150.000 files) takes about one minute to hash on one virtual CPU using `SHA265` hashing.
