use sled::Db;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use data_encoding::HEXUPPER;
use ring::digest::{Context, Digest, SHA256};
use walkdir::{DirEntry, WalkDir};

use crate::config::Config;
use crate::hashing;
use crate::notifiers::Dispatcher;
use crate::persist::upsert_hashes;

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

pub async fn hash_file(path: &Path) -> std::io::Result<String> {
    let input = File::open(path)?;
    let reader = BufReader::new(input);
    let digest = sha256_digest(reader).await?;

    let hash_digest = HEXUPPER.encode(digest.as_ref());
    Ok(hash_digest)
}

fn ignore_paths(entry: &DirEntry) -> bool {
    entry.path().is_dir() || entry.path().is_symlink()
}

/// Initialize the file hash database
pub async fn init_hash_db(config: Config) {
    let database_path = config.database_path();
    if database_path.exists() {
        info!(
            "database already found at: {:?}. Deleting.",
            config.database_path()
        );
        std::fs::remove_dir_all(database_path);
    }

    let db = sled::open(database_path).unwrap();

    let directories = config.directories();
    for directory in directories {
        info!("process directory: {:?}", &directory);

        upsert_hash_tree(&db, directory).await;
    }
}

/// Starts walking a `start_path`, hashes all files and stores the hashes together with the
/// path in a database `db`.
async fn upsert_hash_tree(db: &Db, start_path: &Path) -> std::io::Result<()> {
    let mut index = 0;

    let walker = WalkDir::new(start_path).into_iter();
    for entry in walker {
        let file_path_entry = entry?.to_owned();

        if ignore_paths(&file_path_entry) {
            continue;
        }

        let fp = file_path_entry.clone();
        let hash = hashing::hash_file(fp.path()).await.unwrap();
        upsert_hashes(&db, file_path_entry.clone(), &hash).unwrap_or_else(|mut e| {
            e.dispatch();
        });
        index += 1;
    }

    db.flush()?;
    info!("Hashed {} files", index);
    Ok(())
}
