use sled;

fn check_hashes(db: &sled::Db, file_path: &str, file_hash: &str) -> sled::Result<()> {
    assert_eq!(db.get(file_path)?, Some(sled::IVec::from(file_hash)),);
    println!("finished checking");
    Ok(())
}

pub fn update_hashes(db: &sled::Db, file_path: &str, file_hash: &str) -> std::io::Result<()> {
    // insert and get, similar to std's BTreeMap
    let old_value = db.insert(file_path, file_hash)?;

    // block until all operations are stable on disk
    // (flush_async also available to get a Future)
    Ok(())
}
