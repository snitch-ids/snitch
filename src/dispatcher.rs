use chatterbox::message::{Dispatcher, Message, Notification};
use chrono::{DateTime, Utc};
use lazy_static::lazy_static;
use reqwest::header::{HeaderMap, AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast::error::SendError as BroadcastSendError;
use tokio::sync::mpsc::{channel, Receiver, Sender};

lazy_static! {
    static ref HOSTNAME: String = hostname::get()
        .expect("failed to get hostname")
        .to_str()
        .unwrap()
        .to_owned();
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct MessageBackend {
    pub hostname: String,
    pub title: String,
    pub body: String,
    pub timestamp: DateTime<Utc>,
}

impl Notification for MessageBackend {
    fn message(&self) -> Message {
        let title = self.title.clone();
        let body = format!("{}\n\n{}\n{}", self.body, *HOSTNAME, self.timestamp);
        Message { title, body }
    }
}

impl MessageBackend {
    pub fn new_now(title: String, body: String) -> Self {
        let timestamp = Utc::now();
        Self {
            hostname: HOSTNAME.clone(),
            title,
            body,
            timestamp,
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct ConfigBackend {
    pub token: String,
    pub url: String,
}

pub struct SnitchDispatcher {
    pub dispatcher_chatterbox: Dispatcher,
    pub sender: Sender<MessageBackend>,
}

struct BackendActor<T> {
    receiver: Receiver<T>,
    config: ConfigBackend,
}

impl<T: Serialize> BackendActor<T> {
    async fn run(&mut self) {
        while let Some(message) = self.receiver.recv().await {
            self.send_message(message).await;
        }
    }

    async fn send_message(&self, message: T) {
        debug!("sending to backend.");
        let client = reqwest::Client::new();

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            format!("Bearer {}", self.config.token).parse().unwrap(),
        );

        headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        let url = self.config.url.clone() + "/messages";
        let response = match client
            .post(url)
            .json(&message)
            .headers(headers)
            .send()
            .await
        {
            Ok(response) => response,
            Err(err) => {
                error!("{err:?}");
                return;
            }
        };

        match response.error_for_status_ref() {
            Ok(response) => debug!("response: {:?}", response),
            Err(err) => {
                warn!("{err:?}");
            }
        }
    }
}

impl SnitchDispatcher {
    pub fn new(
        config_chatterbox: chatterbox::dispatcher::Sender,
        config_backend: ConfigBackend,
    ) -> Self {
        let dispatcher_chatterbox = Dispatcher::new(config_chatterbox);
        let (sender, receiver) = channel::<MessageBackend>(1000);
        let mut actor = BackendActor {
            receiver,
            config: config_backend,
        };
        tokio::spawn(async move { actor.run().await });
        Self {
            dispatcher_chatterbox,
            sender,
        }
    }

    pub async fn dispatch(
        &self,
        message: MessageBackend,
    ) -> Result<(), BroadcastSendError<String>> {
        self.dispatcher_chatterbox.dispatch(&message).await?;
        self.sender.send(message).await.unwrap();
        Ok(())
    }

    pub async fn send_test_message(&self) -> Result<(), BroadcastSendError<String>> {
        self.dispatch(MessageBackend::new_now(
            "test".to_string(),
            "test".to_string(),
        ))
        .await?;
        Ok(())
    }
}

//
// #[cfg(test)]
// mod tests {
//     use super::*;
//
//     #[tokio::test]
//     async fn test_send_message() {
//         let dispatcher = SnitchDispatcher::new(Default::default(), Default::default());
//         // dispatcher.send_message("test".to_string()).await.unwrap();
//     }
// }}
