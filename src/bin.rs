#[macro_use]
extern crate log;

use std::path::Path;
use std::process;
use std::time::{Duration, Instant};

use env_logger::Builder;
use eyre::{Result, WrapErr};
use log::LevelFilter;

use crate::authentication_logs::watch_authentication_logs;
use crate::cli::Cli;
use crate::dispatcher::{ConfigBackend, SnitchDispatcher};
use crate::hashing::{init_hash_db, watch_files};
use clap::Parser;

use crate::config::{load_config_from_file, print_basic_config};
use crate::persist::{accept_files, validate_hashes};
mod authentication_logs;
mod check;
mod cli;
mod config;
mod dispatcher;
#[cfg(all(feature = "ebpf", target_os = "linux"))]
mod ebpf;
mod hashing;
mod heartbeat;
mod persist;
mod style;
mod test_utils;
mod verity;

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
    if args.check {
        let ok = check::run(config_file).await;
        process::exit(if ok { 0 } else { 1 });
    }

    let config = load_config_from_file(config_file)
        .wrap_err(format!("failed loading config file: {:?}", config_file))?;
    let sender = config.sender.clone();
    let config_backend = ConfigBackend {
        token: config.token.clone(),
        url: config.url.clone(),
    };
    let dispatcher = SnitchDispatcher::new(sender, config_backend);
    let start = Instant::now();

    debug!("start!");
    if args.init {
        init_hash_db(&config, &dispatcher, args.root.as_deref().map(Path::new))
            .await
            .map_err(|err| {
                error!("{err}");
                process::exit(1);
            })
            .unwrap();
    } else if !args.accept.is_empty() {
        accept_files(&config, &args.accept)
            .await
            .wrap_err("accepting files")?;
    } else if args.scan {
        validate_hashes(&config, &dispatcher)
            .await
            .map_err(|err| {
                warn!("Failed scanning files: {err}");
                process::exit(1);
            })
            .expect("Checking files failed");
    } else if args.watch {
        #[cfg(all(feature = "ebpf", target_os = "linux"))]
        match ebpf::unavailable() {
            // If loading or running the BPF programs fails, watching goes on
            // with inotify; the heartbeat reports the mode change.
            None => {
                if let Err(err) = ebpf::watch_ebpf(&config, &dispatcher).await {
                    error!("BPF file monitoring failed: {err:?}");
                    warn!("watching with inotify instead");
                    watch_files(&config, &dispatcher).await;
                }
            }
            Some(reason) => {
                warn!(
                    "watching with inotify, not with BPF LSM programs: {reason} (snitch --check \
                     tells how to change that)"
                );
                watch_files(&config, &dispatcher).await;
            }
        }
        #[cfg(not(all(feature = "ebpf", target_os = "linux")))]
        watch_files(&config, &dispatcher).await;
    } else if args.watch_files {
        watch_files(&config, &dispatcher).await;
    } else if args.watch_ebpf {
        #[cfg(all(feature = "ebpf", target_os = "linux"))]
        ebpf::watch_ebpf(&config, &dispatcher)
            .await
            .wrap_err("BPF file monitoring failed")?;
        #[cfg(not(all(feature = "ebpf", target_os = "linux")))]
        {
            error!("this snitch was built without BPF support (Linux, cargo feature `ebpf`)");
            process::exit(1);
        }
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
    tokio::time::sleep(Duration::from_millis(1000)).await;

    Ok(())
}
