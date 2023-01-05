use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::broadcast::Receiver;

use crate::dispatcher::{DispatchError, Example, Handler};
use log::debug;

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Telegram {
    pub bot_token: String,
    pub chat_id: String,
}

impl Example for Telegram {
    fn example() -> Self {
        Telegram {
            bot_token: "92349823049:DFIPJEXAMPLE-EXAMPLE123d-EXAMPLE".to_string(),
            chat_id: "1234567890".to_string(),
        }
    }
}

impl Handler for Telegram {
    fn check(&self) -> Result<(), DispatchError> {
        todo!()
    }

    fn start_handler(self, receiver: Receiver<String>) {
        let mut handler = TelegramHandler {
            config: self,
            receiver,
        };
        tokio::spawn(async move {
            handler.start().await;
        });
    }
}

pub struct TelegramHandler {
    pub(crate) config: Telegram,
    pub(crate) receiver: Receiver<String>,
}

impl TelegramHandler {
    async fn send(&self, message: String) -> Result<(), reqwest::Error> {
        let url = format!(
            "https://api.telegram.org/bot{}/sendMessage",
            &self.config.bot_token
        );

        let mut params: HashMap<&str, &str> = HashMap::new();
        params.insert("text", &message);
        params.insert("chat_id", &self.config.chat_id);
        params.insert("parse_mode", "html");

        let mut headers = HeaderMap::new();
        headers.insert("Accept", "application/json".parse().unwrap());
        headers.insert(
            "User-Agent",
            "Telegram Bot SDK - (https://github.com/irazasyed/telegram-bot-sdk)"
                .parse()
                .unwrap(),
        );
        headers.insert("Content-Type", "application/json".parse().unwrap());

        debug!("dispatching telegram message");

        let client = reqwest::Client::new();
        client
            .post(url)
            .headers(headers)
            .json(&params)
            .send()
            .await?;
        debug!("sent telegram message");
        Ok(())
    }

    pub async fn start(&mut self) {
        loop {
            let data = self.receiver.recv().await;
            match data {
                Err(e) => {
                    debug!("{}", e);
                    break;
                }
                Ok(data) => self.send(data).await.expect("failed sending message"),
            }
        }
    }
}

#[test]
fn test_example() {
    Telegram::example();
}
