use crate::dispatcher::{DispatchError, Example, Handler};
use crate::message::Message;
use reqwest::header::{HeaderMap, AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use serde_json;
use tokio::sync::broadcast::Receiver;

#[cfg(not(test))]
use log::{debug, info, warn};

#[cfg(test)]
use std::{println as info, println as warn, println as debug};
use tokio::sync::broadcast::error::RecvError; // Workaround to use prinltn! for logs.

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Backend {
    pub url: String,
    pub token: String, // replace with MessageToken
}

impl Example for Backend {
    fn example() -> Self {
        Self {
            url: "http://localhost:8080/messages/".to_string(),
            token: "INSERTTOKENHERE".to_string(),
        }
    }
}

impl Handler for Backend {
    fn check(&self) -> Result<(), DispatchError> {
        if self.token.len() == 0 {
            return Err(DispatchError::Check(
                "Token length should not be 0".to_string(),
            ));
        }
        Ok(())
    }

    fn start_handler(self, receiver: Receiver<String>) {
        self.check().expect("check failed");
        let mut backend_handler = BackendHandler {
            config: self,
            receiver,
        };
        tokio::spawn(async move {
            backend_handler.start().await;
        });
        warn!("started backend handlers");
    }
}

pub struct BackendHandler {
    pub(crate) config: Backend,
    pub(crate) receiver: Receiver<String>,
}

/// Dispatch a message to the backend
async fn send(config: &Backend, message_content: &str) {
    let message = Message::new_now(&"Failure", message_content.to_owned());
    info!("sending to backend. ");
    let as_json = serde_json::to_string(&message).unwrap();
    let client = reqwest::Client::new();
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        format!("Bearer {}", config.token).parse().unwrap(),
    );
    headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());

    let response = client
        .post(config.url.clone())
        .body(as_json)
        .headers(headers)
        .send()
        .await
        .expect("failed sending message");

    match response.error_for_status_ref() {
        Ok(_res) => (),
        Err(err) => {
            debug!("{err:?}");
        }
    }
}

impl BackendHandler {
    pub async fn start(&mut self) {
        loop {
            match self.receiver.recv().await {
                Ok(data) => {
                    send(&self.config, &data).await;
                }
                Err(e) => {
                    debug!("{}", e);
                    break;
                }
            }
        }
    }
}

#[test]
fn test_example() {
    Backend::example();
}

#[tokio::test]
async fn test_backend() {
    let backend_config = Backend {
        url: "http://api.snitch.cool/messages/".to_string(),
        // token: "!!!INSECUREADMINTOKEN!!!".to_string(),
        token: "Hm7RoI85N7I9NwjN1igy9ysyh9PGRZqd".to_string(),
    };

    let message = "TESTMESSAGE";
    send(&backend_config, message).await;
}
