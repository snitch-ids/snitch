use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::str::from_utf8;

use crate::{hashing, notify_hash_changed, DB_DIRECTORY};
use sled;
use walkdir::DirEntry;

pub struct HashMismatch {
    pub file_path: String,
}

impl fmt::Display for HashMismatch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Hashes dont match")
    }
}

// A unique format for debugging output
impl fmt::Debug for HashMismatch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "HashMismatch {{ file_path: {} }}", self.file_path)
    }
}

pub fn upsert_hashes(db: &sled::Db, fp: DirEntry, file_hash: &str) -> Result<(), HashMismatch> {
    let file_path = fp.path().to_str().unwrap();
    let old_value = db
        .insert(file_path, file_hash)
        .expect("something went wrong persisting the hash");

    match old_value {
        Some(v) => {
            if v != file_hash {
                return Err(HashMismatch {
                    file_path: String::from(file_path),
                });
            }
        }
        None => (),
    }
    Ok(())
}

pub async fn check_files(config: BTreeMap<String, Vec<String>>) -> Result<(), HashMismatch> {
    let db = sled::open(Path::new(DB_DIRECTORY)).unwrap();

    for key in db.iter() {
        let vec = key.unwrap();
        let vec_str = from_utf8(&vec.0).unwrap();
        let former_hash = from_utf8(&vec.1).unwrap();

        let fp = Path::new(&vec_str);
        validate_hash(fp, former_hash).await.unwrap_or_else(|e| {
            notify_hash_changed(e);
        });
    }

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
