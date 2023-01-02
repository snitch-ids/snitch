pub mod backend;
pub mod email;
pub mod slack;
pub mod telegram;

use email::Email;
use slack::Slack;
use telegram::Telegram;

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio::sync::broadcast::Receiver;

use log::debug;

/// Bind a handler to a receiver channel if the handler is not `None`.
macro_rules! setup_handler {
    ($handler:expr, $receiver:expr) => {{
        if let Some(config) = $handler {
            let rx = $receiver.subscribe();
            config.start_handler(rx);
            debug!("started handler");
        }
    }};
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Default, Clone)]
pub struct Sender {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) telegram: Option<Telegram>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) email: Option<Email>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) slack: Option<Slack>,
}

impl Example for Sender {
    fn example() -> Self {
        Self {
            telegram: Some(Telegram::example()),
            email: Some(Email::example()),
            slack: Some(Slack::example()),
        }
    }
}

impl Sender {
    pub fn setup_dispatcher(self, tx: &broadcast::Sender<String>) {
        setup_handler!(self.telegram, tx);
        setup_handler!(self.email, tx);
        setup_handler!(self.slack, tx);
    }
}

trait Handler {
    fn start_handler(self, receiver: Receiver<String>);
}

pub trait Example {
    fn example() -> Self;
}

#[test]
fn test_default_config() {
    println!("{:?}", Sender::example());
}
