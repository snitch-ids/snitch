use sled::Db;
use std::error::{self, Error};
use std::fs::File;
use std::hash::Hash;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use std::str::Utf8Error;
use std::{fmt, fs};

extern crate notify;

use data_encoding::HEXUPPER;
use multi_dispatcher::message::Dispatcher;
use notify::{raw_watcher, RawEvent, RecursiveMode, Watcher};
use ring::digest::{Context, Digest, SHA256};
use std::sync::mpsc::channel;
use walkdir::WalkDir;

use crate::config::Config;
use crate::entropy;
use crate::entropy::Entropy;
use crate::persist::{open_database, upsert_hashes};
use crate::style::get_progressbar;

type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

#[derive(Debug, Clone)]
pub struct HashData {
    pub(crate) digest: String,
    pub(crate) entropy: f32,
}

impl HashData {
    fn to_string(&self) -> String {
        format!("{}:{}", self.digest, self.entropy)
    }

    pub fn from_string(data: &str) -> Self {
        let s = data.split(":").collect::<Vec<_>>();
        Self {
            digest: s[0].parse().unwrap(),
            entropy: s[1].parse().unwrap(),
        }
    }
}

/// Calculate a `SHA256` hash from `reader`.
async fn sha256_digest<R: Read>(mut reader: R, length: f32) -> std::io::Result<HashData> {
    let mut context = Context::new(&SHA256);
    let mut buffer = [0; 1024];
    let mut entropy = Entropy::new();

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
        entropy.update(&buffer[..count])
    }

    let e = entropy.shannon_entropy(length);
    let digest = context.finish();
    let hex_digest = HEXUPPER.encode(digest.as_ref());
    let hash_data = HashData {
        digest: hex_digest,
        entropy: e,
    };
    Ok(hash_data)
}

/// calculate the hash of a file located at `path`.
pub async fn hash_file(path: &Path) -> std::io::Result<HashData> {
    let mut input = File::open(path)?;
    let length = input.metadata().unwrap().len();

    let reader = BufReader::new(input);

    let hash_data = sha256_digest(reader, length as f32).await?;

    Ok(hash_data)
}

#[derive(Debug)]
pub enum HashDBError {
    SledError(sled::Error),
}

impl Error for HashDBError {}

impl fmt::Display for HashDBError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "An error occurred while interacting with the database!")
    }
}

impl From<sled::Error> for HashDBError {
    fn from(e: sled::Error) -> Self {
        HashDBError::SledError(e)
    }
}

/// Initialize the file hash database
pub async fn init_hash_db(config: &Config, dispatcher: &Dispatcher) -> Result<()> {
    let database_path = config.database_path();

    let db = open_database(&database_path)?;
    let progressbar = get_progressbar(config.directories().len() as u64, 1);
    for directory in config.directories() {
        progressbar.inc(1);
        progressbar.set_message(format!("{}", directory.display()));
        upsert_hash_tree(&db, config, dispatcher, directory).await?;
    }
    progressbar.finish_with_message(format!("database checksum: {}", db.checksum()?));

    Ok(())
}

/// Returns `true` if `entry` is either a symbolic link or a directory
fn is_symlink_or_directory(entry: &Path) -> bool {
    entry.is_dir() || entry.is_symlink()
}

/// Starts walking a `start_path`, hashes all files and stores the hashes together with the
/// path in a database `db`.
async fn upsert_hash_tree(
    db: &Db,
    config: &Config,
    dispatcher: &Dispatcher,
    start_path: &Path,
) -> std::io::Result<()> {
    let walker = WalkDir::new(start_path)
        .into_iter()
        .filter_entry(|e| !config.is_excluded_directory(e));

    for entry in walker {
        match entry {
            Err(err) => {
                warn!("{err}");
                continue;
            }
            Ok(value) => check_file_hash(value.path(), db, dispatcher).await,
        };
    }

    db.flush_async().await?;
    Ok(())
}

async fn check_file_hash(file_path_entry: &Path, db: &Db, dispatcher: &Dispatcher) {
    if is_symlink_or_directory(file_path_entry) {
        // info!("skipping symlink/directory: {:?}", file_path_entry);
        return;
    }

    match hash_file(file_path_entry).await {
        Ok(hash_data) => {
            upsert_hashes(db, file_path_entry, &hash_data.to_string()).unwrap_or_else(|e| {
                dispatcher.dispatch(&e);
            });
        }
        Err(err) => {
            warn!("{err} on {:?}. Skipping.", file_path_entry);
        }
    }
}

pub async fn watch_files(config: &Config, dispatcher: &Dispatcher) {
    // Create a channel to receive the events.
    let (tx, rx) = channel();

    // Create a watcher object, delivering raw events.
    // The notification back-end is selected based on the platform.
    let mut watcher = raw_watcher(tx).unwrap();

    // Add a path to be watched. All files and directories at that path and
    // below will be monitored for changes.
    for directory in config.directories() {
        info!("adding watcher for {:?}", directory);
        watcher.watch(directory, RecursiveMode::Recursive).unwrap();
    }

    let db = open_database(&config.database_path()).unwrap();

    loop {
        match rx.recv() {
            Ok(RawEvent {
                path: Some(path),
                op: Ok(_op),
                ..
            }) => {
                check_file_hash(&path, &db, dispatcher).await;
            }
            Ok(event) => println!("broken event: {:?}", event),
            Err(e) => println!("watch error: {:?}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::hashing::HashData;

    #[test]
    fn test_hash_data() {
        let h = HashData {
            digest: "digest".to_string(),
            entropy: 1.0,
        };
        let _ = HashData::from_string(h.to_string());
    }
}
