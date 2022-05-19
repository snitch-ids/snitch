use serde::{Deserialize, Serialize};

pub mod email;
pub mod telegram;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Dispatcher {
    pub enable_email: bool,
    pub enable_telegram: bool,
}

impl Dispatcher {
    pub fn dispatch<T: Notification>(&self, notification: &T) {
        let message = notification.message();
        let message_mail = message.clone();
        let message_telegram = message.clone();

        tokio::spawn(async move {
            telegram::send_telegram(message_telegram).await.expect("Failed sending notification via telegram");
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

/// Structs implementing this trait can be dispatched with the [Dispatcher](Dispatcher).
pub trait Notification {

    /// An implementation of this method returns a `String` that will be dispatched to the user.
    fn message(&self) -> String;
}

pub struct BasicNotification {
    pub message: String,
}

impl Notification for BasicNotification {
    fn message(&self) -> String {
        return self.message.clone();
    }
}
