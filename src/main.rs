mod hashing;
mod persist;

use hashing::hash_file;
use persist::update_hashes;
use ring::digest::Digest;
use sled::Db;
use std::path::Path;
use std::time::{Duration, Instant};
use walkdir::WalkDir;

static DB_FILE: &str = "/tmp/nitros.db";

fn main() {
    let start = Instant::now();
    hash_tree();
    let duration = start.elapsed();

    println!("Time elapsed in expensive_function() is: {:?}", duration);
}

pub fn hash_tree() -> std::io::Result<()> {
    let db = sled::open(DB_FILE)?;
    let start_path = Path::new(".");
    let mut index = 0;
    for entry in WalkDir::new(start_path) {
        let file_path_entry = entry.unwrap();
        let file_path = file_path_entry.path();
        if file_path.is_dir() {
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
