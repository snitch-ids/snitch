#[macro_use]
extern crate log;

use std::path::Path;
use std::process;
use std::time::{Duration, Instant};

use chatterbox::message::Dispatcher;
use env_logger::Builder;
use eyre::{Result, WrapErr};
use log::LevelFilter;

use crate::authentication_logs::watch_authentication_logs;
use crate::hashing::{init_hash_db, watch_files};

use crate::cli::Cli;
use clap::Parser;

use crate::config::{load_config_from_file, print_basic_config};
use crate::persist::validate_hashes;
mod authentication_logs;
mod cli;
mod config;
mod hashing;
mod persist;
mod style;
mod test_utils;

fn setup_logging(args: &Cli) {
    let filter_level = match args.verbose {
        true => LevelFilter::Debug,
        false => LevelFilter::Info,
    };

    Builder::new().filter_level(filter_level).init();
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();
    setup_logging(&args);

    if args.demo_config {
        print_basic_config().wrap_err("failed printing basic config")?;
        process::exit(0);
    }

    let config_file = Path::new(&args.config);

    let config = load_config_from_file(config_file)
        .wrap_err(format!("failed loading config file: {:?}", config_file))?;
    let sender = config.sender.clone();
    let dispatcher = Dispatcher::new(sender);
    let start = Instant::now();

    debug!("start!");
    if args.init {
        config.clear_database();
        init_hash_db(&config, &dispatcher)
            .await
            .map_err(|err| {
                error!("{err}");
                process::exit(1);
            })
            .unwrap();
    } else if args.scan {
        validate_hashes(&config, &dispatcher)
            .await
            .map_err(|err| {
                warn!("Failed scanning files: {err}");
                process::exit(1);
            })
            .expect("Checking files failed");
    } else if args.watch_files {
        watch_files(&config, &dispatcher).await;
    } else if args.watch_authentications {
        watch_authentication_logs(&dispatcher, &config)
            .await
            .expect("failed starting log file watching");
    } else if args.send_test_message {
        dispatcher
            .send_test_message()
            .await
            .expect("failed sending test message");
    }
    debug!("Time elapsed: {:?}", start.elapsed());
    dispatcher.stop();

    tokio::time::sleep(Duration::from_millis(1000)).await;

    Ok(())
}
