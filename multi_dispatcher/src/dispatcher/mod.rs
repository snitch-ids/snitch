pub mod email;
pub mod slack;
pub mod telegram;

use email::Email;
use slack::Slack;
use telegram::Telegram;

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio::sync::broadcast::Receiver;

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
    pub fn setup_dispatcher(self, channel_capacity: usize) -> broadcast::Sender<String> {
        let (tx, rx_telegram) = broadcast::channel::<String>(channel_capacity);

        if let Some(config) = self.telegram {
            config.start_handler(rx_telegram);
        }

        if let Some(config) = self.email {
            let rx_email = tx.subscribe();
            config.start_handler(rx_email);
        }

        if let Some(config) = self.slack {
            let rx_slack = tx.subscribe();
            config.start_handler(rx_slack);
        }

        tx
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
    println!("{:?}", Sender::demo_sender());
}
