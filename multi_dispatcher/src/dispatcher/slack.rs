use crate::dispatcher::{DispatchError, Example, Handler};
use crate::message::Message;

use serde::{Deserialize, Serialize};
use slack_hook::{PayloadBuilder, Slack as SlackHook};
use tokio::sync::broadcast::Receiver;

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Slack {
    #[serde(default)]
    pub webhook_url: String,

    #[serde(default)]
    pub channel: String,
}

impl Example for Slack {
    fn example() -> Self {
        Self {
            webhook_url: "examples-webhook.com".to_string(),
            channel: "#blabla".to_string(),
        }
    }
}

impl Handler for Slack {
    fn check(&self) -> Result<(), DispatchError> {
        todo!()
    }

    fn start_handler(self, receiver: Receiver<String>) {
        let mut handler = SlackHandler {
            config: self,
            receiver,
        };
        tokio::spawn(async move {
            handler.start().await;
        });
    }
}

/// Send messages to slack webhook
pub async fn send_message(
    webhook_url: &str,
    channel: &str,
    message: Message<'_>,
) -> Result<(), slack_hook::Error> {
    let slack = SlackHook::new(webhook_url).unwrap();
    let p = PayloadBuilder::new()
        .text(message.markdown())
        .channel(channel)
        .username("Snitch")
        .icon_emoji(":varys:")
        .build()
        .unwrap();

    slack.send(&p)
}

pub struct SlackHandler {
    pub(crate) config: Slack,
    pub(crate) receiver: Receiver<String>,
}

impl SlackHandler {
    fn self_test(&self, config: &Slack) {
        assert!(config.channel.starts_with('#'));
    }

    pub async fn start(&mut self) {
        loop {
            if let Ok(data) = self.receiver.recv().await {
                let message: Message = serde_json::from_str(&data).unwrap();
                send_message(&self.config.webhook_url, &self.config.webhook_url, message)
                    .await
                    .expect("failed sending on slack");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use needs_env_var::*;

    #[test]
    fn test_example() {
        Slack::example();
    }

    #[tokio::test]
    async fn test_dispatch_example() {
        use std;

        let webhook_url = std::env::var("SNITCH_SLACK_WEBHOOK_URL").unwrap_or_default();
        let channel = std::env::var("SNITCH_SLACK_CHANNEL").unwrap_or_default();

        let test_message = Message::test_example();
        send_message(&webhook_url, &channel, test_message)
            .await
            .unwrap();
    }
}
