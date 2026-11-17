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
    let config = Config::demo_config();
    println!("{}", serde_yaml::to_string(&config)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::config::Config;

    #[test]
    fn test_basic_config() {
        let _x = Config::demo_config();
    }
}
