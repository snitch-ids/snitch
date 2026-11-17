//! Heartbeats to the backend: a dead-man switch.
//!
//! While snitch watches a host, it sends `POST {url}/heartbeat` every
//! `heartbeat_interval` seconds. The backend alerts when they stop, when
//! snitch restarts or the host reboots, and when a heartbeat is forged.
//!
//! Each snitch process is a session with a random key that only it knows.
//! With `--watch-ebpf` loaded at boot, nobody can read it from this process's
//! memory. The first heartbeat registers the key with the backend (over
//! TLS). Every heartbeat is signed with HMAC-SHA256 over its body and has a
//! larger sequence number than the one before. So whoever stops snitch can't
//! keep its heartbeats going: another sender is another session, and the
//! backend reports a restart.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use data_encoding::HEXLOWER;
use reqwest::header::CONTENT_TYPE;
use reqwest::StatusCode;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;

use crate::config::Config;
use crate::dispatcher::HOSTNAME;

/// Hex HMAC-SHA256 of the body, keyed with the session key.
const SIGNATURE_HEADER: &str = "X-Snitch-Signature";

/// How snitch watches the host.
#[allow(dead_code)] // the library has no `--watch-ebpf`
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// `--watch-ebpf`, programs loaded at boot with self-protection.
    Protected,
    /// `--watch-ebpf`, programs loaded by snitch itself.
    Unprotected,
    /// `--watch-files` (inotify).
    Files,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SelfTest {
    pub ok: bool,
    pub detail: String,
}

/// What the heartbeat reports about the watcher.
#[derive(Debug, Clone, Serialize)]
pub struct Health {
    pub mode: Mode,
    /// `None` until the first self-test, and in modes without one.
    pub selftest: Option<SelfTest>,
    /// Events the BPF programs couldn't deliver (ring buffer full).
    pub events_dropped: u64,
    /// Refused tamper attempts.
    pub tamper_blocked: u64,
    /// Files from the hash database that are watched (BPF modes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub watched: Option<u64>,
}

pub type SharedHealth = Arc<Mutex<Health>>;

#[derive(Serialize)]
struct Heartbeat<'a> {
    hostname: &'a str,
    boot_id: &'a str,
    session: &'a str,
    seq: u64,
    interval: u64,
    sent_at: DateTime<Utc>,
    version: &'static str,
    /// SHA-256 of the configuration file and its path: a restart with
    /// another configuration (e.g. one that watches nothing) is reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    config: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    config_path: Option<&'a str>,
    #[serde(flatten)]
    health: Health,
    /// Until the backend has accepted a heartbeat of this session.
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<&'a str>,
}

/// Shared health for the watcher; sends heartbeats with it if a backend
/// token is configured.
pub fn start(config: &Config, mode: Mode) -> SharedHealth {
    let health = Arc::new(Mutex::new(Health {
        mode,
        selftest: None,
        events_dropped: 0,
        tamper_blocked: 0,
        watched: None,
    }));
    if config.token.is_empty() {
        return health;
    }
    if config.heartbeat_interval == 0 {
        info!("heartbeats off (heartbeat_interval: 0)");
        return health;
    }
    match Sender::new(config) {
        Ok(sender) => {
            info!("heartbeat every {} s to {}", sender.interval, config.url);
            tokio::spawn(sender.run(health.clone()));
        }
        Err(err) => error!("no heartbeats: {err}"),
    }
    health
}

struct Sender {
    client: reqwest::Client,
    url: String,
    token: String,
    interval: u64,
    boot_id: String,
    session: String,
    key_hex: String,
    key: hmac::Key,
    seq: u64,
    registered: bool,
    failing: bool,
    config: Option<(String, String)>,
}

impl Sender {
    fn new(config: &Config) -> eyre::Result<Self> {
        let rng = SystemRandom::new();
        let mut key = [0u8; 32];
        let mut session = [0u8; 8];
        rng.fill(&mut key)
            .and_then(|_| rng.fill(&mut session))
            .map_err(|_| eyre::eyre!("no random numbers"))?;
        let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map(|s| s.trim().to_owned())
            .unwrap_or_default();
        let interval = config.heartbeat_interval.clamp(10, 3600);
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(interval.min(30)))
                .build()?,
            url: format!("{}/heartbeat", config.url.trim_end_matches('/')),
            token: config.token.clone(),
            interval,
            boot_id,
            session: HEXLOWER.encode(&session),
            key_hex: HEXLOWER.encode(&key),
            key: hmac::Key::new(hmac::HMAC_SHA256, &key),
            seq: 0,
            registered: false,
            failing: false,
            config: config
                .origin
                .as_ref()
                .map(|o| (o.sha256.clone(), o.path.display().to_string())),
        })
    }

    async fn run(mut self, health: SharedHealth) {
        // The first one a few seconds after start, with the first self-test.
        let mut tick = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_secs(5),
            Duration::from_secs(self.interval),
        );
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let health = health.lock().unwrap().clone();
            // Registers again right away if the backend lost the session.
            if self.send(&health).await == Some(StatusCode::CONFLICT) {
                self.send(&health).await;
            }
        }
    }

    async fn send(&mut self, health: &Health) -> Option<StatusCode> {
        self.seq += 1;
        let body = serde_json::to_vec(&Heartbeat {
            hostname: &HOSTNAME,
            boot_id: &self.boot_id,
            session: &self.session,
            seq: self.seq,
            interval: self.interval,
            sent_at: Utc::now(),
            version: env!("CARGO_PKG_VERSION"),
            config: self.config.as_ref().map(|(sha, _)| sha.as_str()),
            config_path: self.config.as_ref().map(|(_, path)| path.as_str()),
            health: health.clone(),
            key: (!self.registered).then_some(self.key_hex.as_str()),
        })
        .expect("heartbeat serializes");
        let signature = HEXLOWER.encode(hmac::sign(&self.key, &body).as_ref());
        let result = self
            .client
            .post(&self.url)
            .bearer_auth(&self.token)
            .header(CONTENT_TYPE, "application/json")
            .header(SIGNATURE_HEADER, signature)
            .body(body)
            .send()
            .await;
        let status = match result {
            Ok(response) => response.status(),
            Err(err) => {
                self.failed(&err.to_string());
                return None;
            }
        };
        if status.is_success() {
            self.registered = true;
            if self.failing {
                info!("heartbeats delivered again");
                self.failing = false;
            }
        } else if status == StatusCode::CONFLICT {
            // The backend doesn't know this session (anymore): send the key.
            debug!("heartbeat: backend asks to register the session");
            self.registered = false;
        } else {
            self.failed(&format!("backend answered {status}"));
        }
        Some(status)
    }

    fn failed(&mut self, why: &str) {
        if self.failing {
            debug!("heartbeat not delivered: {why}");
        } else {
            warn!(
                "heartbeat not delivered: {why}. Retrying every {} s.",
                self.interval
            );
            self.failing = true;
        }
    }
}
