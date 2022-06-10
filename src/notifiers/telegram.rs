use std::collections::HashMap;
use std::env;

use reqwest;
use reqwest::header::HeaderMap;

pub async fn send_message(message: String) -> Result<(), reqwest::Error> {
    let token = env::var("TELEGRAM_BOT_TOKEN").expect("TELEGRAM_BOT_TOKEN not set\n");
    let chat_id = env::var("TELEGRAM_CHAT_ID").expect("TELEGRAM_CHAT_ID not set\n");
    let url = format!("https://api.telegram.org/bot{}/sendMessage", token);

    let mut params = HashMap::new();

    params.insert("text", format!("<i>Nitro</i>\n{}", message));
    params.insert("chat_id", chat_id);
    params.insert("parse_mode", "html".to_owned());

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

#[cfg(test)]
mod tests {

    use super::send_message;

    /// Tests dispatching message. Requires configured TELEGRAM token
    #[tokio::test]
    async fn test_send_message() {
        send_message("unit test".to_string()).await.unwrap();
    }
}
