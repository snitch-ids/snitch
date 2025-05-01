use data_encoding::HEXUPPER;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use ring::digest::{Context, Digest, SHA256};
use sled::Db;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::sync::mpsc::channel;
use thiserror::Error;
use walkdir::WalkDir;

extern crate notify;
use crate::config::Config;
use crate::dispatcher::{MessageBackend, SnitchDispatcher};
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
    Sled(#[from] sled::Error),
    #[error(transparent)]
    IO(#[from] std::io::Error),
    #[error(transparent)]
    Persist(#[from] PersistError),
}

/// Initialize the file hash database
pub async fn init_hash_db(
    config: &Config,
    dispatcher: &SnitchDispatcher,
) -> Result<(), HashDBError> {
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
    dispatcher: &SnitchDispatcher,
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
            Ok(value) => process_path(db, dispatcher, value.path()).await,
        };
    }

    db.flush_async().await?;
    Ok(())
}

async fn process_event(event: Event, dispatcher: &SnitchDispatcher) {
    debug!("processing event: {:?}", event);
    let _ = dispatcher
        .dispatch(event.into())
        .await
        .inspect_err(|e| error!("failed to dispatch message: {:?}", e));
}

impl From<Event> for MessageBackend {
    fn from(event: Event) -> Self {
        let title = match event.kind {
            EventKind::Any => "unknown event",
            EventKind::Access(_) => "accessed",
            EventKind::Create(_) => "created",
            EventKind::Modify(_) => "modified",
            EventKind::Remove(_) => "removed",
            EventKind::Other => "other",
        };
        Self::new_now(
            title.to_string(),
            event
                .paths
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<String>>()
                .join("\n"),
        )
    }
}

async fn process_path(db: &Db, dispatcher: &SnitchDispatcher, path: &Path) {
    debug!("processing path: {}", path.display());
    if is_symlink_or_directory(path) {
        debug!("skipping symlink/directory: {:?}", path);
        return;
    }
    let hash = hash_file(path).await.unwrap_or_else(|err| {
        warn!("{err} on {:?}. Skipping.", path);
        format!("{:?}", err)
    });
    match upsert_hashes(db, path, &hash) {
        Ok(_) => {}
        Err(e) => {
            dispatcher
                .dispatch(e.into())
                .await
                .expect("failed to dispatch error");
        }
    };
}

pub async fn watch_files(config: &Config, dispatcher: &SnitchDispatcher) {
    // Create a channel to receive the events.
    let (tx, rx) = channel();

    // Create a watcher object, delivering raw events.
    // The notification back-end is selected based on the platform.
    let mut watcher = notify::recommended_watcher(tx).unwrap();

    // Add a path to be watched. All files and directories at that path and
    // below will be monitored for changes.
    for directory in config.directories() {
        info!("adding watcher for {:?}", directory);
        watcher.watch(directory, RecursiveMode::Recursive).unwrap();
    }

    for res in rx {
        match res {
            Err(err) => {
                error!("error while watching {:?}", err);
            }
            Ok(event) => {
                process_event(event, dispatcher).await;
            }
        }
    }
}
