pub mod backend;
pub mod email;
pub mod slack;
pub mod telegram;

use backend::Backend;
use email::Email;
use slack::Slack;
use telegram::Telegram;

use log::debug;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::broadcast;
use tokio::sync::broadcast::Receiver;
use validator::ValidationErrors;

#[derive(Error, Debug)]
pub enum DispatchError {
    #[error("Dispatcher test failed {:?}", .0)]
    Check(String),
    #[error("Validation failed {:?}", .0)]
    ValidationError(ValidationErrors),
}

/// Bind a handler to a receiver channel if the handler is not `None`.
macro_rules! setup_handler {
    ($handler:expr, $receiver:expr) => {{
        if let Some(config) = $handler {
            config.check()?;
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

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) backend: Option<Backend>,
}

impl Example for Sender {
    fn example() -> Self {
        Self {
            telegram: Some(Telegram::example()),
            email: Some(Email::example()),
            slack: Some(Slack::example()),
            backend: Some(Backend::example()),
        }
    }
}

impl Sender {
    pub fn setup_dispatcher(self, tx: &broadcast::Sender<String>) -> Result<(), DispatchError> {
        setup_handler!(self.telegram, tx);
        setup_handler!(self.backend, tx);
        setup_handler!(self.email, tx);
        setup_handler!(self.slack, tx);
        Ok(())
    }
}

trait Handler {
    fn check(&self) -> Result<(), DispatchError> {
        Ok(())
    }
    fn start_handler(self, receiver: Receiver<String>);
}

pub trait Example {
    fn example() -> Self;
}

#[test]
fn test_default_config() {
    println!("{:?}", Sender::example());
}
