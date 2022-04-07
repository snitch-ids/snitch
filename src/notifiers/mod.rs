use serde::{Deserialize, Serialize};

pub mod email;
pub mod telegram;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Dispatcher {
    pub enable_email: bool,
    pub enable_telegram: bool,
}

impl Dispatcher {
    pub fn dispatch<T: Notify>(&self, notification: &T) {
        let message = notification.message();
        let message_mail = message.clone();
        let message_telegram = message.clone();

        tokio::spawn(async move {
            telegram::send_telegram(message_telegram).await;
        });
        tokio::spawn(async move {
            email::send_mail(message_mail).await;
        });
    }

    pub fn new(enable_email: bool, enable_telegram: bool) -> Dispatcher {
        Dispatcher {
            enable_email,
            enable_telegram,
        }
    }
}

pub trait Notify {
    fn message(&self) -> String;
}

pub struct Notification {
    pub message: String,
}

impl Notify for Notification {
    fn message(&self) -> String {
        return self.message.clone();
    }
}
