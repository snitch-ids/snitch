use crate::dispatcher::Sender;
use chrono::{DateTime, Utc};
use lazy_static::lazy_static;
use log::{debug, warn};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

lazy_static! {
    static ref HOSTNAME: String = hostname::get().unwrap().to_str().unwrap().to_string();
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Message<'a> {
    pub hostname: &'a str,
    pub title: &'a str,
    pub content: String,
    pub timestamp: DateTime<Utc>,
}

impl<'a> Message<'a> {
    pub fn new_now(title: &'a str, content: String) -> Self {
        let timestamp = Utc::now();
        Message {
            hostname: &HOSTNAME,
            title,
            content,
            timestamp,
        }
    }

    pub(crate) fn as_json(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }

    pub(crate) fn from_json(data: &'a str) -> Self {
        serde_json::from_str(&data).expect("failed json message")
    }

    pub(crate) fn html(&self) -> String {
        format!(
            "<b>{}</b>\nhost: {}\n{}\n{}",
            self.title, self.hostname, self.content, self.timestamp
        )
    }

    pub(crate) fn markdown(&self) -> String {
        format!(
            "*{}*\nhost: {}\n{}\n{}",
            self.title, self.hostname, self.content, self.timestamp
        )
    }

    pub(crate) fn test_example() -> Self {
        Self {
            hostname: &HOSTNAME,
            title: "Test Message",
            content: "This message was sent to test connectivity".to_string(),
            timestamp: Utc::now(),
        }
    }
}

impl Notification for Message<'_> {
    fn message(&self) -> Message {
        self.clone()
    }
}

pub struct Dispatcher {
    tx: broadcast::Sender<String>,
}

impl Dispatcher {
    pub fn new(sender: Sender) -> Self {
        let (tx, _) = broadcast::channel::<String>(100);

        sender
            .setup_dispatcher(&tx)
            .expect("setting up dispatcher failed");
        debug!("created sender channel");
        Self { tx }
    }

    pub fn dispatch<T: Notification>(&self, notification: &T) {
        debug!("dispatching message");
        let message = notification.message();
        if let Some(error) = self.tx.send(message.as_json()).err() {
            warn!("Failed sending message. Reason: {}", error);
        }
    }

    pub fn send_test_message(&self) {
        let message = Message::test_example();
        self.dispatch(&message);
    }

    pub fn stop(self) {
        drop(self.tx);
    }
}

/// Structs implementing this trait can be dispatched with the [Dispatcher](Dispatcher).
pub trait Notification {
    /// An implementation of this method returns a `String` that will be dispatched to the user.
    fn message(&self) -> Message;
}
