use crate::dispatcher::{DispatchError, Example, Handler};
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

pub struct SlackHandler {
    pub(crate) config: Slack,
    pub(crate) receiver: Receiver<String>,
}

impl SlackHandler {
    fn self_test(&self, config: &Slack) {
        assert!(config.channel.starts_with('#'));
    }

    /// Send messages to slack webhook
    pub async fn send(&self, message: String) -> Result<(), slack_hook::Error> {
        self.self_test(&self.config);

        let slack = SlackHook::new(&*self.config.webhook_url.as_str()).unwrap();
        let p = PayloadBuilder::new()
            .text(message)
            .channel(&self.config.channel)
            .username("Snitch")
            .icon_emoji(":varys:")
            .build()
            .unwrap();

        slack.send(&p)
    }

    pub async fn start(&mut self) {
        loop {
            let data = self.receiver.recv().await.unwrap();
            self.send(data).await.expect("failed sending on slack");
        }
    }
}
