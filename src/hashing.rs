use sled::Db;
use std::error::{self, Error};
use std::fmt;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
extern crate notify;

use data_encoding::HEXUPPER;
use notify::{raw_watcher, RawEvent, RecursiveMode, Watcher};
use ring::digest::{Context, Digest, SHA256};
use std::sync::mpsc::channel;
use walkdir::{DirEntry, WalkDir};

use crate::config::Config;
use crate::hashing;
use crate::notifiers::Dispatcher;
use crate::persist::{open_database, upsert_hashes};

pub static NITRO_DATABASE_PATH: &str = "/etc/snitch/db";

type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

/// Calculate a `SHA256` hash from `reader`.
async fn sha256_digest<R: Read>(mut reader: R) -> std::io::Result<Digest> {
    let mut context = Context::new(&SHA256);
    let mut buffer = [0; 1024];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }

    Ok(context.finish())
}

/// calculate the hash of a file located at `path`.
pub async fn hash_file(path: &Path) -> std::io::Result<String> {
    let input = File::open(path)?;
    let reader = BufReader::new(input);
    let digest = sha256_digest(reader).await?;

    let hash_digest = HEXUPPER.encode(digest.as_ref());
    Ok(hash_digest)
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
pub async fn init_hash_db(config: Config) -> Result<()> {
    let database_path = Path::new(NITRO_DATABASE_PATH);
    if database_path.exists() {
        info!("database already found at: {:?}. Deleting.", database_path);
        std::fs::remove_dir_all(database_path).expect("Failed deleting database.");
    }

    let db = open_database()?;

    for directory in config.directories() {
        info!("process directory: {:?}", &directory);
        upsert_hash_tree(&db, &config.notifications, directory).await?;
    }
    info!("database checksum: {}", db.checksum()?);
    Ok(())
}

/// Returnes `true` if `entry` is either a symbolic link or a directory
fn is_symlink_or_directory(entry: &Path) -> bool {
    entry.is_dir() || entry.is_symlink()
}

/// Filters excluded paths such as the database path of snitch
fn is_excluded(entry: &DirEntry) -> bool {
    entry
        .path()
        .to_str()
        .map(|s| s.starts_with(NITRO_DATABASE_PATH))
        .unwrap_or(false)
}

/// Starts walking a `start_path`, hashes all files and stores the hashes together with the
/// path in a database `db`.
async fn upsert_hash_tree(
    db: &Db,
    dispatcher: &Dispatcher,
    start_path: &Path,
) -> std::io::Result<()> {
    let walker = WalkDir::new(start_path)
        .into_iter()
        .filter_entry(|e| !is_excluded(e));

    for entry in walker {
        let entry_checked = match entry {
            Err(err) => {
                warn!("{err}");
                continue;
            }
            Ok(value) => value,
        };

        let file_path_entry = entry_checked.to_owned();
        check_file_hash(file_path_entry.path(), db, dispatcher).await;
    }

    db.flush_async().await?;
    Ok(())
}

async fn check_file_hash(file_path_entry: &Path, db: &Db, dispatcher: &Dispatcher) {
    debug!("checking file hash {:?}", file_path_entry);
    if is_symlink_or_directory(file_path_entry) {
        debug!("is symlink. skipping.");
        return;
    }
    let hash = hashing::hash_file(file_path_entry)
        .await
        .unwrap_or_else(|err| {
            warn!("{err} on {:?}. Skipping.", file_path_entry);
            format!("{:?}", err)
        });
    upsert_hashes(db, file_path_entry, &hash).unwrap_or_else(|e| {
        dispatcher.dispatch(&e);
    });
}

pub async fn watch_files(config: Config) {
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

    let db = open_database().unwrap();

    loop {
        match rx.recv() {
            Ok(RawEvent {
                path: Some(path),
                op: Ok(op),
                cookie,
            }) => {
                check_file_hash(&path, &db, &config.notifications).await;
            }
            Ok(event) => println!("broken event: {:?}", event),
            Err(e) => println!("watch error: {:?}", e),
        }
    }
}
