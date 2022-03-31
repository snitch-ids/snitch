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
    let message = message.clone();
    let message_mail = message.clone();

    tokio::spawn(async move {
        telegram::send_telegram(message).await;
    });
    tokio::spawn(async move {
        email::send_mail(message_mail).await;
    });
}
