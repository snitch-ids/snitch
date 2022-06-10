use std::fmt;
use std::path::Path;
use std::str::from_utf8;

use crate::{
    hashing::{self, NITRO_DATABASE_PATH},
    notifiers::{BasicNotification, Dispatcher, Notification},
};
use indicatif::ProgressBar;
use sled;

pub struct HashMismatch {
    pub file_path: String,
}

impl fmt::Display for HashMismatch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Hashes dont match: {}", self.file_path)
    }
}

impl fmt::Debug for HashMismatch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "File was modified: {{ file_path: {} }}", self.file_path)
    }
}

impl Notification for HashMismatch {
    fn message(&self) -> String {
        self.file_path.to_string()
    }
}

pub fn upsert_hashes(db: &sled::Db, fp: &Path, file_hash: &str) -> Result<(), HashMismatch> {
    let file_path = fp.to_str().unwrap();
    let old_value = db
        .insert(file_path, file_hash)
        .expect("something went wrong persisting the hash");

    match old_value {
        Some(v) => {
            if v != file_hash {
                return Err(HashMismatch {
                    file_path: file_path.to_string(),
                });
            }
        }
        None => (),
    }
    Ok(())
}

pub async fn validate_hashes(dispatcher: &Dispatcher) -> Result<(), HashMismatch> {
    let db = sled::open(NITRO_DATABASE_PATH).unwrap();
    let n_items = db.len() as u64;
    let pb = ProgressBar::new(n_items);

    for key in db.iter() {
        pb.inc(1);
        let vec = key.unwrap();
        let vec_str = from_utf8(&vec.0).unwrap();
        let former_hash = from_utf8(&vec.1).unwrap();

        let fp = Path::new(&vec_str);

        if !fp.exists() {
            let message: String = format!(
                "directory <b>{}</b> does not exist but was previously there",
                fp.display()
            )
            .to_string();

            let notification = BasicNotification { message: message };
            dispatcher.dispatch(&notification);
            continue;
        }

        validate_hash(fp, former_hash).await.unwrap_or_else(|e| {
            dispatcher.dispatch(&e);
        });
    }
    pb.finish_with_message("done");
    info!("database checksum: {}", db.checksum().unwrap());

    Ok(())
}

async fn validate_hash(fp: &Path, former_hash: &str) -> Result<(), HashMismatch> {
    if !fp.exists() {
        warn!("the file does not exist anymore!! {}", fp.to_str().unwrap())
    }
    let hash = hashing::hash_file(&fp).await;
    if hash.unwrap() != former_hash {
        return Err(HashMismatch {
            file_path: String::from(fp.to_str().unwrap()),
        });
    }

    Ok(())
}
