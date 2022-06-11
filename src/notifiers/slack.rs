extern crate slack_hook;
use slack_hook::{PayloadBuilder, Slack};
use std::env;

/// Send messages to slack webhook
pub async fn send_message(message: String) -> Result<(), reqwest::Error> {
    let webhook = env::var("SLACK_WEBHOOK_URL").expect("SLACK_WEBHOOK_URL not set\n");
    let channel = env::var("SLACK_CHANNEL").expect("SLACK_CHANNEL not set\n");
    assert!(channel.starts_with("#"));

    let slack = Slack::new(webhook.as_str()).unwrap();
    let p = PayloadBuilder::new()
        .text("test message")
        .channel(channel)
        .username("Snitch")
        .icon_emoji(":chart_with_upwards_trend:")
        .build()
        .unwrap();

    let res = slack.send(&p);
    match res {
        Ok(()) => println!("ok"),
        Err(x) => println!("ERR: {:?}", x),
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    use std::time::SystemTime;

    use super::send_message;

    /// Tests dispatching message. Requires configured SLACK configration
    #[tokio::test]
    async fn test_send_message() {
        let now = SystemTime::now();
        let message = format!("unit test {:?}", now);
        send_message(message).await.unwrap();
    }
}
