use crate::dispatcher::{DispatchError, Example, Handler};
use crate::message::Message;
use reqwest::header::{HeaderMap, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Url;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_json;
use tokio::sync::broadcast::Receiver;
use url::ParseError;

use validator::Validate;

#[cfg(not(test))]
use log::{debug, info};

use log::warn;
use serde::ser::SerializeStruct;
use std::str::FromStr;
#[cfg(test)]
use std::{println as info, println as debug};

#[derive(Validate, Debug, PartialEq, Clone)]
pub struct Backend {
    pub url: Url,
    #[validate(length(equal = 32))]
    pub token: String, // replace with MessageToken
}

impl Serialize for Backend {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Backend", 2)?;
        state.serialize_field("url", &self.url.as_str())?;
        state.serialize_field("token", &self.token)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Backend {
    fn deserialize<D>(deserializer: D) -> Result<Backend, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct BackendHelper {
            url: String,
            token: String,
        }

        let helper = BackendHelper::deserialize(deserializer)?;
        let url = Url::parse(&helper.url).map_err(de::Error::custom)?;

        Ok(Backend {
            url,
            token: helper.token,
        })
    }
}

fn expand_backend_url(url: &Url) -> Result<Url, ParseError> {
    let url = url.join("/messages")?;
    Ok(url)
}

impl Example for Backend {
    fn example() -> Self {
        Self {
            url: Url::from_str("https://api.snitch.cool").unwrap(),
            token: "INSERTTOKENHERE".to_string(),
        }
    }
}

impl Handler for Backend {
    fn check(&self) -> Result<(), DispatchError> {
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
        debug!("started backend handlers");
    }
}

pub struct BackendHandler {
    pub(crate) config: Backend,
    pub(crate) receiver: Receiver<String>,
}

impl BackendHandler {
    fn new(config: Backend, receiver: Receiver<String>) -> Self {
        Self { config, receiver }
    }
}

/// Dispatch a message to the backend
async fn send_message(config: &Backend, message: Message<'_>) {
    info!("sending to backend. ");
    let as_json = serde_json::to_string(&message).unwrap();
    let client = reqwest::Client::new();
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        format!("Bearer {}", config.token).parse().unwrap(),
    );
    headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
    let url = expand_backend_url(&config.url).expect("failed expanding url");
    let response = client
        .get(url)
        .body(as_json)
        .headers(headers)
        .send()
        .await
        .expect("failed sending message");

    if response.status() != reqwest::StatusCode::OK {
        warn!("response status: {:?}", response.status());
    };

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
            if let Ok(data) = self.receiver.recv().await {
                let message = Message::from_json(&data);
                send_message(&self.config, message).await;
            } else {
                break;
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
        Backend::example();
    }

    #[test]
    #[ignore]
    fn test_bad_token() {
        let mut example = Backend::example();
        example.token = "".to_string();
        assert!(example.check().is_err());
    }

    #[tokio::test]
    #[ignore]
    async fn test_dispatch_example() {
        use std;

        let token = std::env::var("SNITCH_BACKEND_TOKEN").unwrap_or_default();
        let config = Backend {
            url: Url::from_str("https://api.snitch.cool").unwrap(),
            token,
        };
        let test_message = Message::test_example();
        send_message(&config, test_message).await;
    }
}
