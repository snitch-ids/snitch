#![feature(generators)]
#[macro_use]
extern crate log;

use std::path::Path;
use std::process;
use std::time::{Duration, Instant};

use clap::StructOpt;
use env_logger::Builder;
use log::LevelFilter;
use tokio::time;

use crate::authentication_logs::watch_authentication_logs;
use crate::hashing::init_hash_db;

use crate::cli::Cli;
use crate::config::{load_config_from_file, print_basic_config};
use crate::notifiers::Dispatcher;
use crate::persist::validate_hashes;

mod authentication_logs;
mod cli;
mod config;
mod hashing;
mod notifiers;
mod persist;

static DEFAULT_CONFIG: &str = "/etc/nitro/config.yaml";

#[tokio::main]
async fn main() {
    Builder::new().filter_level(LevelFilter::Info).init();
    let args = Cli::parse();

    if args.demo_config == true {
        print_basic_config();
        process::exit(0);
    }
    let config = load_config_from_file(Path::new(DEFAULT_CONFIG)).unwrap();

    let dispatcher = Dispatcher::new(false, false, false);
    let start = Instant::now();
    if args.init == true {
        init_hash_db(&dispatcher, &config).await;
    } else if args.scan == true {
        validate_hashes(&dispatcher)
            .await
            .expect("Checking files failed");
    } else if args.watch_authentication {
        watch_authentication_logs(&dispatcher, &config).await;
    }
    debug!("Time elapsed to hash: {:?}", start.elapsed());

    debug!("Waiting a second for dispatcher to complete");
    time::sleep(Duration::from_millis(1000)).await;
}

#[cfg(test)]
pub mod test_util {
    use chrono::Utc;

    pub fn get_test_message() -> String {
        let host_str = hostname::get().unwrap();
        let host = host_str.to_str().unwrap();
        let now = Utc::now();
        format!("unit test {:?}\nhost: {}", now, host)
    }
}
