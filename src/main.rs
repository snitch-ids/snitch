use std::path::Path;
use std::process;
use std::time::Instant;

use clap::Parser;
use walkdir::{DirEntry, WalkDir};

use notifiers::notify_hash_changed;
use persist::upsert_hashes;

use crate::config::{load_config_from_file, print_basic_config};
use crate::persist::HashMismatch;

mod config;
mod hashing;
mod notifiers;
mod persist;
#[macro_use]
extern crate log;
use env_logger::Builder;
use log::LevelFilter;
static DB_DIRECTORY: &str = "/tmp/nitros.db";
static DEFAULT_CONFIG: &str = "/etc/nitro/config.yaml";

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// print a demo configuration
    #[clap(long)]
    demo_config: bool,
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
    let directories = config.get("directories").unwrap();

    let start = Instant::now();
    for directory in directories {
        info!("process directory: {}", directory);
        let start_path = Path::new(directory);
        if !start_path.exists() {
            warn!("configured path {:?} does not exist", start_path);
        }
        hash_tree(start_path).await;
    }
    let duration = start.elapsed();
    info!("Time elapsed to hash: {:?}", duration);
}

fn ignore_paths(entry: &DirEntry) -> bool {
    entry.path().is_dir() || entry.path().is_symlink()
}

pub async fn hash_tree(start_path: &Path) -> std::io::Result<()> {
    let db = sled::open(Path::new(DB_DIRECTORY))?;
    let mut index = 0;

    let walker = WalkDir::new(start_path).into_iter();
    for entry in walker {
        let file_path_entry = entry?.to_owned();

        if ignore_paths(&file_path_entry) {
            continue;
        }

        let fp = file_path_entry.clone();
        let hash = hashing::hash_file(fp).await.unwrap();
        upsert_hashes(&db, file_path_entry.clone(), &hash).unwrap_or_else(|e| {
            notify_hash_changed(e);
        });
        index += 1;
    }

    db.flush()?;
    info!("Hashed {} files", index);
    Ok(())
}
