use reqwest;
use reqwest::header::HeaderMap;
use std::collections::HashMap;
use std::env;

use serde::{Deserialize, Serialize};

use super::Message;

pub async fn send_message(message: Message) -> Result<(), reqwest::Error> {
    let url = format!("http://127.0.0.1:8080/messages/");

    let mut headers = HeaderMap::new();
    headers.insert("Accept", "application/json".parse().unwrap());
    headers.insert("Content-Type", "application/json".parse().unwrap());

    debug!("dispatching message");

    let client = reqwest::Client::new();
    client
        .post(url)
        .headers(headers)
        .json(&message)  // TODO: why doesnt this work???
        .send()
        .await?;
    debug!("sent message");
    Ok(())
}

#[cfg(test)]
mod tests {

    use super::send_message;
    use crate::test_util::get_test_message;

    /// Tests dispatching message. Requires configured TELEGRAM configuration
    #[tokio::test]
    async fn test_send_message() {
        let message = get_test_message();
        send_message(message).await.unwrap();
    }
}
