use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::{env, process};
use walkdir::DirEntry;
mod default;
mod macos;
mod windows;
use eyre::{Context, ContextCompat, Result};

/// Snitch configurations
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub directories: Vec<String>,
    pub sender: multi_dispatcher::dispatcher::Sender,
    pub authentication_logs: Option<String>,
    pub snitch_root: String,
}

impl Config {
    pub fn database_path(&self) -> PathBuf {
        let database_path = Path::new(&self.snitch_root).join(Path::new("db"));
        assert!(database_path.is_absolute());
        database_path
    }

    pub fn clear_database(&self) {
        if self.database_path().exists() {
            info!(
                "database already found at: {:?}. Deleting.",
                &self.database_path()
            );
            std::fs::remove_dir_all(&self.database_path()).expect("Failed deleting database.");
        }
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

    /// Filters excluded paths such as the database path of snitch
    pub fn is_excluded_directory(&self, directory: &DirEntry) -> bool {
        directory
            .path()
            .parent()
            .expect("failed getting parent directory")
            == self.database_path()
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
    let reader = std::fs::File::open(path)
        .wrap_err(format!("Failed opening config file {:?}", path.to_owned()))?;

    let config = serde_yaml::from_reader(reader)?;

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
