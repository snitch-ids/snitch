use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::{env, process};
mod default;
mod macos;
mod windows;
use eyre::{Context, Result};

/// Snitch configurations
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub directories: Vec<String>,
    pub sender: chatterbox::dispatcher::Sender,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication_logs: Option<PathBuf>,
    #[serde(default = "Config::default_root")]
    pub snitch_root: String,
    #[serde(default = "Config::default_url")]
    pub url: String,
    #[serde(default = "Config::default_token")]
    pub token: String,
    /// Seconds between heartbeats to the backend while snitch watches the
    /// host (needs a token); 0 turns them off.
    #[serde(default = "Config::default_heartbeat_interval")]
    pub heartbeat_interval: u64,
    /// Where the configuration came from (reported in heartbeats).
    #[serde(skip)]
    pub origin: Option<ConfigOrigin>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConfigOrigin {
    pub path: PathBuf,
    /// SHA-256 of the file (lower-case hex)
    pub sha256: String,
}

impl Config {
    pub(crate) fn default_token() -> String {
        "PASTEYOURTOKENHERE".to_string()
    }
}

impl Config {
    pub(crate) fn default_url() -> String {
        "https://api.snitch.cool".to_string()
    }

    pub(crate) fn default_heartbeat_interval() -> u64 {
        60
    }

    pub(crate) fn default_root() -> String {
        "/etc/snitch/".to_string()
    }
}

impl Config {
    pub fn database_path(&self) -> PathBuf {
        let database_path = Path::new(&self.snitch_root).join(Path::new("db"));
        assert!(database_path.is_absolute());
        database_path
    }

    /// get directories as a vector of Paths. Non-existent directories will be ignored with a warning.
    pub fn directories(&self) -> Vec<&Path> {
        let paths = self
            .directories
            .iter()
            .map(Path::new)
            .filter(|dir| check_directory_exists(dir))
            .collect();
        paths
    }

    /// get a basic configuration for demonstration. On Ubuntu and Debian this should be a good starting point.
    pub fn demo_config() -> Config {
        match env::consts::OS {
            "macos" => macos::get_config(),
            "windows" => windows::get_config(),
            _ => default::get_config(),
        }
    }
}

fn check_directory_exists(directory: &Path) -> bool {
    if !directory.exists() {
        warn!("no such directory: {:?}. Ignoring.", directory);
        return false;
    }
    true
}

/// Load the configuration from a file and return a [`Config`](Config) struct.
pub fn load_config_from_file(path: &Path) -> Result<Config> {
    if !path.exists() {
        println!("No config file: {:?}\nTip: run\n\n  snitch --demo-config > /etc/snitch/config.yaml\n\nto get started.", path);
        process::exit(1);
    }
    let bytes = std::fs::read(path)
        .wrap_err(format!("Failed opening config file {:?}", path.to_owned()))?;

    let mut config: Config = serde_yaml::from_slice(&bytes)?;
    config.origin = Some(ConfigOrigin {
        path: std::path::absolute(path).unwrap_or_else(|_| path.to_owned()),
        sha256: data_encoding::HEXLOWER
            .encode(ring::digest::digest(&ring::digest::SHA256, &bytes).as_ref()),
    });

    Ok(config)
}

pub fn print_basic_config() -> Result<()> {
    print!("{}", demo_config_text()?);
    Ok(())
}

/// `snitch --demo-config`: a commented configuration to start from, with the
/// default directories that exist here and aren't symlinks.
pub fn demo_config_text() -> Result<String> {
    let demo = Config::demo_config();
    let directories: Vec<&String> = demo
        .directories
        .iter()
        .filter(|d| std::fs::symlink_metadata(d).is_ok_and(|m| m.is_dir()))
        .collect();
    let senders: String = serde_yaml::to_string(&demo.sender)?
        .lines()
        .map(|l| format!("#  {l}\n"))
        .collect();
    Ok(format!(
        "# snitch configuration. `snitch --check` tells what works and what's missing.

# Directories whose files snitch hashes (snitch --init) and watches.
directories:
{directories}
# Where snitch keeps its hash database (<snitch_root>/db).
snitch_root: {root}

# The backend gets snitch's messages and heartbeats, and alerts you when a
# host stops sending them. Get a token at https://snitch.cool (or from your
# own backend). Without one, snitch only logs.
url: {url}
token: ''

# Seconds between heartbeats (with a token); 0 turns them off.
heartbeat_interval: {interval}

# Notifications that snitch sends itself, besides the backend, e.g.:
#sender:
{senders}sender: {{}}
",
        directories = serde_yaml::to_string(&directories)?,
        root = serde_yaml::to_string(&demo.snitch_root)?.trim_end(),
        url = serde_yaml::to_string(&demo.url)?.trim_end(),
        interval = demo.heartbeat_interval,
    ))
}

#[cfg(test)]
mod tests {
    use crate::config::Config;

    #[test]
    fn test_basic_config() {
        let _x = Config::demo_config();
    }

    #[test]
    fn demo_config_text_parses() {
        let text = super::demo_config_text().unwrap();
        let config: Config = serde_yaml::from_str(&text).unwrap();
        assert!(config.token.is_empty());
        assert_eq!(config.sender, chatterbox::dispatcher::Sender::default());
        assert!(!config.directories.is_empty());
        assert!(text.contains("#  telegram:"));
    }
}
