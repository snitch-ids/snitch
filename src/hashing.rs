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

pub static NITRO_DATABASE_PATH: &str = "/etc/nitro/db";

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

/// Initialize the file hash database
pub async fn init_hash_db(dispatcher: &Dispatcher, config: &Config) {
    let database_path = Path::new(NITRO_DATABASE_PATH);
    if database_path.exists() {
        info!("database already found at: {:?}. Deleting.", database_path);
        std::fs::remove_dir_all(database_path).expect("Failed deleting database.");
    }
    let db_config = sled::Config::default()
        .path(NITRO_DATABASE_PATH)
        .cache_capacity(10_000_000_000)
        .flush_every_ms(Some(10000000));

    let db = db_config.open().unwrap();

    let directories = config.directories();
    for directory in directories {
        if !directory.exists() {
            warn!("no such directory: {:?}", directory);
            continue;
        }
        info!("process directory: {:?}", &directory);
        upsert_hash_tree(&db, dispatcher, directory)
            .await
            .expect("Failed updating hash");
    }

    let p = Path::new(NITRO_DATABASE_PATH);
    upsert_hash_tree(&db, dispatcher, p)
        .await
        .expect("Failed updating hash");
}

/// Returnes `true` if `entry` is either a symbolic link or a directory
fn is_symlink_or_directory(entry: &DirEntry) -> bool {
    entry.file_type().is_dir() || entry.path().is_symlink()
}

/// Filters excluded paths such as the database path of nitro
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
    let mut index = 0;

    let walker = WalkDir::new(start_path)
        .into_iter()
        .filter_entry(|e| !is_excluded(e));

    for entry in walker {
        let file_path_entry = entry?.to_owned();

        if is_symlink_or_directory(&file_path_entry) {
            continue;
        }

        let hash = hashing::hash_file(file_path_entry.path()).await.unwrap();
        upsert_hashes(&db, file_path_entry.path(), &hash).unwrap_or_else(|e| {
            dispatcher.dispatch(&e);
        });
        index += 1;
    }

    db.flush_async().await?;
    info!("Hashed {} files", index);
    Ok(())
}
