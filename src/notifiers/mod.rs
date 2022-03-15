use std::path::Path;
use serde_yaml::Value::String;
use walkdir::DirEntry;
use crate::HashMismatch;

pub mod email;
pub mod telegram;

pub async fn notify_hash_changed(hash_mismatch_error: HashMismatch) {
    telegram::send_telegram(hash_mismatch_error.file_path).await;
}
