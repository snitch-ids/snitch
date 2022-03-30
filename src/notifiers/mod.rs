pub mod email;
pub mod telegram;

pub trait Dispatcher {
    fn dispatch(&mut self) {
        notify_hash_changed(self.message());
    }

    fn message(&mut self) -> String;
}

pub struct Notification {
    pub message: String,
}

impl Dispatcher for Notification {
    fn message(&mut self) -> String {
        format!("{}", self.message)
    }
}

pub fn notify_hash_changed(message: String) {
    let file_path_telegram = message.clone();
    let file_path_mail = message.clone();
    warn!("{}", file_path_mail);

    tokio::spawn(async move {
        telegram::send_telegram(file_path_telegram).await;
    });
    tokio::spawn(async move {
        email::send_mail(file_path_mail).await;
    });
}
