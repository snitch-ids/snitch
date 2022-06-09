use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process;

use crate::notifiers::Dispatcher;

/// Nitro configurations
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub directories: Vec<String>,
    pub notifications: Dispatcher,
    pub authentication_logs: String,
}

impl Config {
    /// get directories as a vector of Paths.
    pub fn directories(&self) -> Vec<&Path> {
        let mut paths = vec![];
        for dir in self.directories.iter() {
            paths.push(Path::new(dir));
        }
        paths
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
                enable_telegram: false,
            },
        }
    }
}

/// Load the configuration from a file and return a [`Config`](Config) struct.
pub fn load_config_from_file(path: &Path) -> Result<Config, serde_yaml::Error> {
    if !path.exists() {
        println!("No config file: {:?}\nTip: run\n\n  nitro --demo-config > /etc/nitro/config.yaml\n\nto get started.", path);
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
        let x = Config::demo_config();
    }
}
