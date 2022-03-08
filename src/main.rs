mod hashing;

use std::path::Path;
use ring::digest::Digest;
use hashing::hash_tree;
use sled;

static DB_FILE: &str = "/tmp/noinu.db";

fn main() {
    let file_path = Path::new("/tmp/test");
    let file_path_str: &str = file_path.to_str().unwrap();

    let hash = hashing::hash_file(file_path).unwrap();
    update_hashes(file_path_str, &hash).unwrap();
    check_hashes(file_path_str, &hash).unwrap();
}

fn check_hashes(file_path: &str, file_hash: &str) -> std::io::Result<()>{
    let tree = sled::open(DB_FILE)?;
    assert_eq!(
      tree.get(file_path)?,
      Some(sled::IVec::from(file_hash)),
    );
    tree.flush()?;
    println!("finished checking");
    Ok(())
}

fn update_hashes(file_path: &str, file_hash: &str) -> std::io::Result<()> {
    let tree = sled::open(DB_FILE)?;

    // insert and get, similar to std's BTreeMap
    let old_value = tree.insert(file_path, file_hash)?;

    // block until all operations are stable on disk
    // (flush_async also available to get a Future)
    tree.flush()?;
    println!("finished persisting");
    Ok(())
}

