pub mod email;
pub mod telegram;

pub trait Dispatcher {
    fn dispatch(&mut self) {
        notify_hash_changed(self.message());
    }

    fn message(&mut self) -> String;
}

pub fn notify_hash_changed(message: String) {
    let file_path_telegram = message.clone();
    let file_path_mail = message.clone();
    warn!("intrusion: {}", file_path_mail);

    tokio::spawn(async move {
        telegram::send_telegram(file_path_telegram).await.unwrap();
    });
    tokio::spawn(async move {
        email::send_mail(file_path_mail).await;
    });
}
