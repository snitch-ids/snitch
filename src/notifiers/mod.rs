use crate::HashMismatch;

pub mod email;
pub mod telegram;

pub fn notify_hash_changed(hash_mismatch_error: HashMismatch) {
    let file_path_telegram = hash_mismatch_error.file_path.clone();
    let file_path_mail = hash_mismatch_error.file_path.clone();
    warn!("intrusion: {}", file_path_mail);

    tokio::spawn(async move {
        telegram::send_telegram(file_path_telegram).await;
    });
    tokio::spawn(async move {
        email::send_mail(file_path_mail).await;
    });
}
