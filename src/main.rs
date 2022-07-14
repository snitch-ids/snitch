#![feature(generators)]
#[macro_use]
extern crate log;

use std::path::Path;
use std::process;
use std::time::Instant;

use clap::StructOpt;
use env_logger::Builder;
use log::LevelFilter;

use crate::authentication_logs::watch_authentication_logs;
use crate::hashing::init_hash_db;

use crate::cli::Cli;
use crate::config::{load_config_from_file, print_basic_config};
use crate::persist::validate_hashes;

mod authentication_logs;
mod cli;
mod config;
mod hashing;
mod notifiers;
mod persist;

fn setup_logging(args: &Cli) {
    let filter_level = match args.verbose {
        true => LevelFilter::Debug,
        false => LevelFilter::Info,
    };

    Builder::new().filter_level(filter_level).init();
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();
    setup_logging(&args);

    if args.demo_config == true {
        print_basic_config();
        process::exit(0);
    }

    let config = load_config_from_file(Path::new(&args.config_file)).unwrap();
    let start = Instant::now();
    if args.init {
        init_hash_db(config)
            .await
            .map_err(|err| {
                error!("{err}");
                process::exit(1);
            })
            .unwrap();
        debug!("Time elapsed: {:?}", start.elapsed());
    } else if args.scan {
        validate_hashes(config)
            .await
            .map_err(|err| {
                println!("Failed scaning files: {err}");
                process::exit(1);
            })
            .expect("Checking files failed");
    } else if args.watch_authentication {
        watch_authentication_logs(&config.notifications, &config).await;
    }
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
