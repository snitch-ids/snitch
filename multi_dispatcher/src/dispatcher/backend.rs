use crate::dispatcher::{Example, Handler};
use log::debug;
use reqwest::header::{HeaderMap, AUTHORIZATION};
use serde::{Deserialize, Serialize};

use tokio::sync::broadcast::Receiver;

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
    fn start_handler(self, receiver: Receiver<String>) {
        let mut backend_handler = BackendHandler {
            config: self,
            receiver,
        };
        tokio::spawn(async move {
            backend_handler.start().await;
        });
        debug!("started backend handlers");
    }
}

pub struct BackendHandler {
    pub(crate) config: Backend,
    pub(crate) receiver: Receiver<String>,
}

/// Dispatch a message to the backend
async fn send(config: &Backend, message: String) {
    let client = reqwest::Client::new();
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        format!("BEARER: {}", config.token).parse().unwrap(),
    );
    let response = client
        .post(config.url.clone())
        .headers(headers)
        .body(message.to_string())
        .send()
        .await;
    println!("response: {response:#?}");
}

impl BackendHandler {
    pub async fn start(&mut self) {
        loop {
            let data = self.receiver.recv().await.unwrap();
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
        url: "http://127.0.0.1:8080/messages/".to_string(),
        token: "M8bf6cTrO0iXE0deqiV85y5NZeNRPNTr".to_string(),
    };
    send(&backend_config, "testmessage".to_string()).await;
}
