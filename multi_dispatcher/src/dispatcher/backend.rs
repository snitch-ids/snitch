use crate::dispatcher::{DispatchError, Example, Handler};
use crate::message::Message;
use reqwest::header::{HeaderMap, AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use serde_json;
use tokio::sync::broadcast::Receiver;

#[cfg(not(test))]
use log::{debug, info, warn};

#[cfg(test)]
use std::{println as info, println as warn, println as debug}; // Workaround to use prinltn! for logs.

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
async fn send(config: &Backend, message_content: String) {
    let message = Message::new_now("Failure".to_string(), message_content);
    info!("sending to backend.... ");
    let as_json = serde_json::to_string(&message).unwrap();
    debug!("payload: {as_json}");
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
            let data = self
                .receiver
                .recv()
                .await
                .expect("failed getting data from receiver");
            send(&self.config, data).await;
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
        url: "http://127.0.0.1:8081/messages/".to_string(),
        token: "!!!INSECUREADMINTOKEN!!!".to_string(),
    };

    let message = Message::new_now("title".to_string(), "content".to_string());
    send(&backend_config, serde_json::to_string(&message).unwrap()).await;
}
