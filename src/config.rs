use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process;
use walkdir::DirEntry;

use crate::notifiers::Dispatcher;

/// Snitch configurations
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub directories: Vec<String>,
    pub notifications: Dispatcher,
    pub authentication_logs: String,
    pub snitch_root: String,
}

fn check_directory_exists(directory: &Path) -> bool {
    if !directory.exists() {
        warn!("no such directory: {:?}. Ignoring.", directory);
        return false;
    }
    true
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

    /// Filters excluded paths such as the database path of snitch
    pub fn is_excluded_directory(&self, directory: &DirEntry) -> bool {
        let db_path = self.database_path();
        directory
            .path()
            .to_str()
            .map(|s| s.starts_with(db_path.to_str().unwrap()))
            .unwrap_or(false)
    }

    /// get a basic configuration for demonstration. On Ubuntu and Debian this should be a good starting point.
    pub fn demo_config() -> Config {
        Config {
            directories: vec![
                "/bin".to_owned(),
                "/sbin".to_owned(),
                "/boot".to_owned(),
                "/root".to_owned(),
                "/usr".to_owned(),
                "/lib".to_owned(),
                "/etc".to_owned(),
            ],
            authentication_logs: "/var/log/auth.log".to_owned(),
            notifications: Dispatcher {
                enable_email: false,
                enable_telegram: true,
                enable_slack: false,
            },
            snitch_root: "/etc/snitch".to_owned(),
        }
    }
}

/// Load the configuration from a file and return a [`Config`](Config) struct.
pub fn load_config_from_file(path: &Path) -> Result<Config, serde_yaml::Error> {
    if !path.exists() {
        println!("No config file: {:?}\nTip: run\n\n  snitch --demo-config > /etc/snitch/config.yaml\n\nto get started.", path);
        process::exit(1);
    }
    let reader = std::fs::File::open(path).unwrap();
    let config = serde_yaml::from_reader(reader)?;

    Ok(config)
}

pub fn print_basic_config() {
    let config = Config::demo_config();
    println!("{}", serde_yaml::to_string(&config).unwrap());
}

#[cfg(test)]
mod tests {
    use crate::config::Config;

    #[test]
    fn test_basic_config() {
        let _x = Config::demo_config();
    }
}
