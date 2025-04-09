use sled::Db;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
extern crate notify;
use data_encoding::HEXUPPER;
use multi_dispatcher::message::Dispatcher;
use notify::{raw_watcher, RawEvent, RecursiveMode, Watcher};
use ring::digest::{Context, Digest, SHA256};
use std::sync::mpsc::channel;
use thiserror::Error;
use walkdir::WalkDir;

use crate::config::Config;
use crate::persist::{open_database, upsert_hashes, PersistError};
use crate::style::get_progressbar;

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

#[derive(Debug, Error)]
pub enum HashDBError {
    #[error(transparent)]
    SledError(#[from] sled::Error),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    PersistError(#[from] PersistError),
}

/// Initialize the file hash database
pub async fn init_hash_db(config: &Config, dispatcher: &Dispatcher) -> Result<(), HashDBError> {
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
        debug!("skipping symlink/directory: {:?}", file_path_entry);
        return;
    }
    let hash = hash_file(file_path_entry).await.unwrap_or_else(|err| {
        warn!("{err} on {:?}. Skipping.", file_path_entry);
        format!("{:?}", err)
    });
    upsert_hashes(db, file_path_entry, &hash).unwrap_or_else(|e| {
        dispatcher.dispatch(&e);
    });
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
