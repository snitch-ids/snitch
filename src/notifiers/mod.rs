pub mod email;
pub mod telegram;

pub async fn notify_hash_changed (file_path: &str){
    println!("hash changed of file {}", file_path);
    telegram::send_telegram(file_path).await;
}
