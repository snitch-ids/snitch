use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::broadcast::Receiver;

use crate::dispatcher::{DispatchError, Example, Handler};
use crate::message::Message;
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

async fn send_telegram(
    bot_token: &str,
    chat_id: &str,
    message: Message<'_>,
) -> Result<(), reqwest::Error> {
    let url = format!("https://api.telegram.org/bot{}/sendMessage", bot_token);
    let text = message.html();
    let mut params: HashMap<&str, &str> = HashMap::new();

    params.insert("text", &text);
    params.insert("chat_id", chat_id);
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

pub struct TelegramHandler {
    pub(crate) config: Telegram,
    pub(crate) receiver: Receiver<String>,
}

impl TelegramHandler {
    pub async fn start(&mut self) {
        loop {
            if let Ok(data) = self.receiver.recv().await {

                let message: Message = serde_json::from_str(&data).unwrap();
                send_telegram(
                    &self.config.bot_token,
                    &self.config.chat_id,
                    message,
                )
                    .await
                    .expect("failed sending message");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Message;
    use needs_env_var::*;

    #[test]
    fn test_example() {
        Telegram::example();
    }

    #[tokio::test]
    async fn test_dispatch_example() {
        use std;

        let bot_token = std::env::var("SNITCH_TELEGRAM_BOT_TOKEN").unwrap_or_default();
        let chat_id = std::env::var("SNITCH_TELEGRAM_CHAT_ID").unwrap_or_default();

        let test_message = Message::test_example();
        send_telegram(&bot_token, &chat_id, test_message)
            .await
            .unwrap();
    }
}
