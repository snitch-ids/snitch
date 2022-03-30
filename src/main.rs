#![feature(generators)]
#[macro_use]
extern crate log;

use std::collections::BTreeMap;
use std::path::Path;
use std::process;
use std::time::Instant;

use clap::Parser;
use env_logger::Builder;
use log::LevelFilter;
use sled::Db;
use walkdir::{DirEntry, WalkDir};

use crate::authentication_logs::watch_authentication_logs;
use crate::notifiers::Dispatcher;
use persist::upsert_hashes;

use crate::config::{load_config_from_file, print_basic_config};
use crate::persist::check_files;

mod authentication_logs;
mod config;
mod hashing;
mod notifiers;
mod persist;

static DB_DIRECTORY: &str = "/tmp/nitros.db";
static DEFAULT_CONFIG: &str = "/etc/nitro/config.yaml";

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// print a demo configuration
    #[clap(long)]
    demo_config: bool,

    /// initialize the database
    #[clap(short, long)]
    init: bool,

    /// Start scanning files
    #[clap(short, long)]
    scan: bool,

    /// Start scanning authentication
    #[clap(short, long)]
    watch_authentication: bool,
}

#[tokio::main]
async fn main() {
    Builder::new().filter_level(LevelFilter::Info).init();
    let args = Cli::parse();

    if args.demo_config == true {
        print_basic_config();
        process::exit(0);
    }
    let config = load_config_from_file(Path::new(DEFAULT_CONFIG)).unwrap();

    let start = Instant::now();
    if args.init == true {
        init(config).await;
    } else if args.scan == true {
        check_files(config).await;
    } else if args.watch_authentication {
        let test_file = Path::new("/tmp/auth.log");
        watch_authentication_logs(&test_file).await;
    }
    info!("Time elapsed to hash: {:?}", start.elapsed());
}

fn ignore_paths(entry: &DirEntry) -> bool {
    entry.path().is_dir() || entry.path().is_symlink()
}

async fn init(config: BTreeMap<String, Vec<String>>) {
    let database_path = Path::new(DB_DIRECTORY);
    if database_path.exists() {
        info!("database already found at: {}. Deleting.", DB_DIRECTORY);
        std::fs::remove_dir_all(database_path);
    }

    let db = sled::open(database_path).unwrap();

    let directories = config.get("directories").unwrap();
    for directory in directories {
        info!("process directory: {}", directory);
        let start_path = Path::new(directory);

        upsert_hash_tree(&db, start_path).await;
    }
}

async fn upsert_hash_tree(db: &Db, start_path: &Path) -> std::io::Result<()> {
    let mut index = 0;

    let walker = WalkDir::new(start_path).into_iter();
    for entry in walker {
        let file_path_entry = entry?.to_owned();

        if ignore_paths(&file_path_entry) {
            continue;
        }

        let fp = file_path_entry.clone();
        let hash = hashing::hash_file(fp.path()).await.unwrap();
        upsert_hashes(&db, file_path_entry.clone(), &hash).unwrap_or_else(|mut e| {
            e.dispatch();
        });
        index += 1;
    }

    db.flush()?;
    info!("Hashed {} files", index);
    Ok(())
}
