use chrono::{DateTime, Utc};
use multi_dispatcher;
use multi_dispatcher::dispatcher::Sender;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

extern crate lazy_static;

fn get_hostname_string() -> String {
    hostname::get().unwrap().to_str().unwrap().to_owned()
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Message {
    pub hostname: String,
    pub title: String,
    pub content: String,
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

pub struct Dispatcher {
    tx: broadcast::Sender<String>,
}

impl Dispatcher {
    pub(crate) fn new(sender: Sender) -> Self {
        let tx = sender.setup_dispatcher(10);
        debug!("created sender channel");
        Self { tx }
    }

    pub fn dispatch<T: Notification>(&self, notification: &T) {
        let message = notification.message();
        if let Some(error) = self.tx.send(message.as_single_string()).err() {
            warn!("Failed sending message {}", error);
        }
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
