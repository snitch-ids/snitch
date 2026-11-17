use data_encoding::HEXUPPER;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use ring::digest::{Context, SHA256};
use sled::Db;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;
use thiserror::Error;
use walkdir::WalkDir;

extern crate notify;
use crate::config::Config;
use crate::dispatcher::{MessageBackend, SnitchDispatcher};
use crate::persist::{open_database, upsert_hashes, PersistError};
use crate::style::get_progressbar;

/// calculate the hash of a file located at `path`.
pub async fn hash_file(path: &Path) -> std::io::Result<String> {
    hash_file_sync(path)
}

/// SHA-256 of the file at `path` (upper-case hex), for blocking threads.
pub fn hash_file_sync(path: &Path) -> std::io::Result<String> {
    let mut input = File::open(path)?;
    let mut context = Context::new(&SHA256);
    let mut buffer = [0; 8192];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }
    Ok(HEXUPPER.encode(context.finish().as_ref()))
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

/// Initialize the file hash database (replacing an existing one).
///
/// With `root`, hash the files below that directory as if it were `/`, for
/// building images: the database goes below `root` too, and its paths leave
/// `root` out.
pub async fn init_hash_db(
    config: &Config,
    dispatcher: &SnitchDispatcher,
    root: Option<&Path>,
) -> Result<(), HashDBError> {
    let under_root = |path: &Path| -> PathBuf {
        match root {
            Some(root) => root.join(path.strip_prefix("/").unwrap_or(path)),
            None => path.to_owned(),
        }
    };
    let database_path = under_root(&config.database_path());
    if database_path.exists() {
        info!("database already found at: {database_path:?}. Deleting.");
        std::fs::remove_dir_all(&database_path)?;
    }
    let directories: Vec<PathBuf> = config
        .directories
        .iter()
        .map(|dir| under_root(Path::new(dir)))
        .filter(|dir| {
            let exists = dir.exists();
            if !exists {
                warn!("no such directory: {dir:?}. Ignoring.");
            }
            exists
        })
        .collect();

    let db = open_database(&database_path)?;
    let progressbar = get_progressbar(directories.len() as u64, 1);
    for directory in &directories {
        progressbar.inc(1);
        progressbar.set_message(format!("{}", directory.display()));
        upsert_hash_tree(&db, dispatcher, directory, &database_path, root).await?;
    }
    progressbar.finish_with_message(format!(
        "{} files, database checksum: {}",
        db.len(),
        db.checksum()?
    ));

    Ok(())
}

/// Returns `true` if `entry` is either a symbolic link or a directory
fn is_symlink_or_directory(entry: &Path) -> bool {
    entry.is_dir() || entry.is_symlink()
}

/// Starts walking a `start_path`, hashes all files and stores the hashes together with the
/// path in a database `db`. The database's own directory is left out. With
/// `root`, the stored paths leave it out.
async fn upsert_hash_tree(
    db: &Db,
    dispatcher: &SnitchDispatcher,
    start_path: &Path,
    database_path: &Path,
    root: Option<&Path>,
) -> std::io::Result<()> {
    let walker = WalkDir::new(start_path)
        .into_iter()
        .filter_entry(|e| !e.path().starts_with(database_path));

    for entry in walker {
        match entry {
            Err(err) => {
                warn!("{err}");
                continue;
            }
            Ok(value) => {
                let path = value.path();
                let key = match root.and_then(|root| path.strip_prefix(root).ok()) {
                    Some(relative) => Path::new("/").join(relative),
                    None => path.to_owned(),
                };
                process_path(db, dispatcher, path, &key).await
            }
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

/// Hash the file at `path` and store it as `key`.
async fn process_path(db: &Db, dispatcher: &SnitchDispatcher, path: &Path, key: &Path) {
    debug!("processing path: {}", path.display());
    if is_symlink_or_directory(path) {
        debug!("skipping symlink/directory: {:?}", path);
        return;
    }
    let hash = hash_file(path).await.unwrap_or_else(|err| {
        warn!("{err} on {:?}. Skipping.", path);
        format!("{:?}", err)
    });
    match upsert_hashes(db, key, &hash) {
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
    let _health = crate::heartbeat::start(config, crate::heartbeat::Mode::Files);
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
