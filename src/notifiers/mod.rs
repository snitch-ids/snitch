use serde::{Deserialize, Serialize};

pub mod email;
pub mod slack;
pub mod telegram;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Dispatcher {
    pub enable_email: bool,
    pub enable_telegram: bool,
    pub enable_slack: bool,
}

impl Dispatcher {
    pub fn dispatch<T: Notification>(&self, notification: &T) {
        debug!("dispatching: {}", notification.message());
        let message = notification.message();

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

    pub fn new(enable_email: bool, enable_telegram: bool, enable_slack: bool) -> Dispatcher {
        Dispatcher {
            enable_email,
            enable_telegram,
            enable_slack,
        }
    }

    fn send_telegram(message: &String) {
        let message_telegram = message.clone();
        tokio::spawn(async move {
            telegram::send_message(message_telegram)
                .await
                .expect("Failed sending notification via telegram");
        });
    }

    fn send_mail(message: &String) {
        let message_mail = message.clone();
        tokio::spawn(async move {
            email::send_message(message_mail).await;
        });
    }

    fn send_slack(message: &String) {
        let message_mail = message.clone();
        tokio::spawn(async move {
            slack::send_message(message_mail).await;
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
        return self.message.clone();
    }
}
