use serde::{Deserialize, Serialize};

pub mod email;
pub mod slack;
pub mod telegram;

#[derive(Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct Dispatcher {
    pub enable_email: bool,
    pub enable_telegram: bool,
    pub enable_slack: bool,
}

impl Dispatcher {
    pub fn dispatch<T: Notification>(&self, notification: &T) {
        let message = notification.message();
        debug!("dispatching notification {message}");

        if self.enable_telegram {
            Dispatcher::send_telegram(&message);
        }
        if self.enable_email {
            Dispatcher::send_mail(&message);
        }
        if self.enable_slack {
            Dispatcher::send_slack(&message);
        }
    }

    fn send_telegram(message: &str) {
        let message_telegram = message.to_owned();
        tokio::spawn(async move {
            telegram::send_message(message_telegram)
                .await
                .expect("Failed sending notification via telegram");
        });
    }

    fn send_mail(message: &str) {
        let message_mail = message.to_owned();
        tokio::spawn(async move {
            email::send_message(message_mail).await;
        });
    }

    fn send_slack(message: &str) {
        let message_mail = message.to_owned();
        tokio::spawn(async move {
            slack::send_message(message_mail).await.unwrap();
        });
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
        self.message.clone()
    }
}
