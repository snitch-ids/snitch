use crate::config::Config;
use crate::hashing;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::from_utf8;
use thiserror::Error;

use crate::dispatcher::{MessageBackend, SnitchDispatcher};
use crate::style::get_progressbar;
use sled::{self, Db};
use tokio::sync::broadcast::error::SendError;

#[allow(clippy::enum_variant_names)]
#[derive(Error, Debug)]
pub enum PersistError {
    #[error(transparent)]
    SledError(#[from] sled::Error),
    #[error(transparent)]
    Utf8Error(#[from] std::str::Utf8Error),
    #[error(transparent)]
    SendError(#[from] SendError<String>),
}

pub struct HashMismatch {
    pub file_path: String,
}

impl fmt::Display for HashMismatch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "File was modified: {}", self.file_path)
    }
}

impl fmt::Debug for HashMismatch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "File was modified: {}", self.file_path)
    }
}

impl From<HashMismatch> for MessageBackend {
    fn from(value: HashMismatch) -> Self {
        MessageBackend::new_now(
            "Hash mismatch".to_string(),
            format!("File was modified: {}", value.file_path),
        )
    }
}

pub fn open_database(path: &PathBuf) -> Result<Db, PersistError> {
    let db_config = sled::Config::default()
        .path(path)
        .cache_capacity(10_000_000)
        .flush_every_ms(Some(10000000));

    let db = db_config.open().inspect_err(|_| {
        println!("Cannot open {:?}", path);
    })?;

    Ok(db)
}

pub fn upsert_hashes(db: &sled::Db, fp: &Path, file_hash: &str) -> Result<(), HashMismatch> {
    debug!("upserting hash for {:?}", fp);
    let file_path = fp.to_str().unwrap();
    if let Some(v) = db
        .insert(file_path, file_hash)
        .expect("something went wrong persisting the hash")
    {
        if v != file_hash {
            debug!("hash mismatch on: {file_path}");
            return Err(HashMismatch {
                file_path: file_path.to_string(),
            });
        }
    }
    Ok(())
}

pub async fn validate_hashes(
    config: &Config,
    dispatcher: &SnitchDispatcher,
) -> Result<(), PersistError> {
    let db = open_database(&config.database_path())?;
    let progressbar = get_progressbar(db.len() as u64, 10);

    for key in db.iter() {
        progressbar.inc(1);
        let vec = key?;
        let vec_str = from_utf8(&vec.0)?;
        let former_hash = from_utf8(&vec.1)?;

        let fp = Path::new(&vec_str);
        if !fp.exists() {
            let message = MessageBackend::new_now(
                "File/directory removed".to_string(),
                fp.to_str().unwrap().to_string(),
            );
            dispatcher.dispatch(message).await?;
            continue;
        }

        match validate_hash(fp, former_hash).await {
            Ok(_) => {}
            Err(e) => {
                warn!("{:?}", e);
                dispatcher.dispatch(e.into()).await?;
            }
        }
    }
    progressbar.finish_with_message("done");
    info!("database checksum: {}", db.checksum()?);

    Ok(())
}

async fn validate_hash(fp: &Path, former_hash: &str) -> Result<(), HashMismatch> {
    if !fp.exists() {
        warn!("the file does not exist anymore! {:?}", fp)
    }
    let hash = hashing::hash_file(fp).await.unwrap_or_else(|err| {
        warn!("{err} on {:?}. Skipping.", fp);
        format!("{:?}", err)
    });

    if hash != former_hash {
        return Err(HashMismatch {
            file_path: String::from(fp.to_str().unwrap()),
        });
    }

    Ok(())
}
