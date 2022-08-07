use chrono::serde::ts_milliseconds;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
extern crate lazy_static;

pub mod backend;
pub mod email;
pub mod slack;
pub mod telegram;

fn get_hostname_string() -> String {
    hostname::get().unwrap().to_str().unwrap().to_owned()
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Message {
    pub hostname: String,
    pub title: String,
    pub content: String,
    #[serde(with = "ts_milliseconds")]
    pub timestamp: DateTime<Utc>,
}

impl Message {
    pub(crate) fn new_now(title: String, content: String) -> Self {
        let timestamp = Utc::now();
        let hostname = get_hostname_string();
        Message {
            hostname,
            title,
            content,
            timestamp,
        }
    }

    pub(crate) fn as_single_string(&self) -> String {
        format!(
            "{}\n{}\n{}\n{}",
            self.title, self.hostname, self.content, self.timestamp
        )
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct Dispatcher {
    pub enable_email: bool,
    pub enable_telegram: bool,
    pub enable_slack: bool,
}

impl Dispatcher {
    pub fn dispatch<T: Notification>(&self, notification: &T) {
        let message = notification.message();
        debug!("dispatching notification {:?}", message);

        if self.enable_telegram {
            Dispatcher::send_telegram(message.clone());
        }
        if self.enable_email {
            Dispatcher::send_mail(message.clone());
        }
        if self.enable_slack {
            Dispatcher::send_slack(message);
        }
    }

    fn send_telegram(message: Message) {
        tokio::spawn(async move {
            telegram::send_message(message)
                .await
                .expect("Failed sending notification via telegram");
        });
    }

    fn send_mail(message: Message) {
        tokio::spawn(async move {
            email::send_message(message).await;
        });
    }

    fn send_slack(message: Message) {
        tokio::spawn(async move {
            slack::send_message(message)
                .await
                .expect("failed sending message to backend {message}");
        });
    }
}

/// Structs implementing this trait can be dispatched with the [Dispatcher](Dispatcher).
pub trait Notification {
    /// An implementation of this method returns a `String` that will be dispatched to the user.
    fn message(&self) -> Message;
}

pub struct BasicNotification {
    pub message: Message,
}

impl Notification for BasicNotification {
    fn message(&self) -> Message {
        self.message.clone()
    }
}
