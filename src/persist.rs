use std::fmt;

use sled;
use walkdir::DirEntry;

pub struct HashMismatch {
    pub file_path: String,
}

// Different error file_paths according to HashMismatch.file_path
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
    // insert and get, similar to std's BTreeMap

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
    // block until all operations are stable on disk
    // (flush_async also available to get a Future)
    Ok(())
}
