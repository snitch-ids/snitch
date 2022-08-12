use reqwest;
use reqwest::header::HeaderMap;

use super::Message;

pub async fn send_message(message: Message) -> Result<(), reqwest::Error> {
    let url = format!("http://localhost:8082/messages/");
    let mut headers = HeaderMap::new();
    headers.insert("Accept", "application/json".parse().unwrap());
    headers.insert("Content-Type", "application/json".parse().unwrap());

    debug!("dispatching message");

    let client = reqwest::Client::new();
    client
        .post(url)
        .headers(headers)
        .json(&message)
        .send()
        .await?;
    debug!("sent message");
    Ok(())
}

#[cfg(test)]
mod tests {

    use super::send_message;
    use crate::test_utils::get_test_message;

    #[tokio::test]
    async fn test_send_message() {
        let message = get_test_message();
        send_message(message).await.unwrap();
    }
}
