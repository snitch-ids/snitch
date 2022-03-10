mod config;
mod email;
mod hashing;
mod persist;

use config::load_config;
use email::send_mail;
use hashing::hash_file;
use persist::update_hashes;

use ring::digest::Digest;
use sled::Db;
use std::path::Path;
use std::time::{Duration, Instant};
use walkdir::WalkDir;

static DB_DIRECTORY: &str = "/tmp/nitros.db";

#[tokio::main]
async fn main() {
    let config_string = "---\ndirectories:\n - .\n - ../amqtt".to_string();
    let config = load_config(&config_string).unwrap();
    let directories = config.get("directories").unwrap();

    let start = Instant::now();
    for directory in directories {
        println!("process {}", directory);
        let start_path = Path::new(directory);
        hash_tree(start_path);
    }
    let duration = start.elapsed();
    println!("Time elapsed to hash: {:?}", duration);
}

pub fn hash_tree(start_path: &Path) -> std::io::Result<()> {
    let db = sled::open(DB_DIRECTORY)?;
    let mut index = 0;
    for entry in WalkDir::new(start_path) {
        let file_path_entry = entry.unwrap();
        let file_path = file_path_entry.path();

        if file_path.is_dir() || file_path.is_symlink(){
            // skipping directories and symlinks for now
            continue;
        }

        let file_path_str = file_path.to_str().unwrap();
        let hash = hashing::hash_file(&file_path).unwrap();
        update_hashes(&db, file_path_str, &hash).unwrap();
        index += 1;
    }

    db.flush()?;
    println!("N files: {}", index);
    Ok(())
}
