pub mod email;
pub mod slack;
pub mod telegram;

use email::Email;
use slack::Slack;
use telegram::Telegram;

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio::sync::broadcast::Receiver;

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Sender {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) telegram: Option<Telegram>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) email: Option<Email>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) slack: Option<Slack>,
}

impl Sender {
    pub fn demo_sender() -> Self {
        let slack = Slack {
            webhook_url: "webhook".to_string(),
            channel: "channel".to_string(),
        };
        let email = Email {
            smtp_user: "".to_string(),
            smtp_password: "".to_string(),
            smtp_server: "".to_string(),
            receiver_address: "test.test@gmail.com".to_string(),
        };
        let telegram = Telegram {
            bot_token: "token".to_string(),
            chat_id: "chat_id".to_string(),
        };

        Self {
            telegram: Some(telegram),
            email: Some(email),
            slack: Some(slack),
        }
    }

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
