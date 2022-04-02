use serde::{Serialize, Deserialize};

pub mod email;
pub mod telegram;

pub trait Dispatcher {
    fn dispatch(&mut self) {
        notify_hash_changed(self.message());
    }

    fn message(&mut self) -> String;
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]

pub struct NotificationConfig {
    pub enable_email: bool,
    pub enable_telegram: bool,
}

pub struct Notification<'a> {
    pub config: &'a NotificationConfig,
    pub message: String,
}

impl <'a> Dispatcher for Notification<'a> {
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
