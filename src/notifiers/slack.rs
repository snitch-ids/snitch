extern crate slack_hook;
use slack_hook::{PayloadBuilder, Slack};
use std::env;

use super::Message;

/// Send messages to slack webhook
pub async fn send_message(message: Message) -> Result<(), slack_hook::Error> {
    let webhook = env::var("SLACK_WEBHOOK_URL").expect("SLACK_WEBHOOK_URL not set\n");
    let channel = env::var("SLACK_CHANNEL").expect("SLACK_CHANNEL not set\n");
    assert!(channel.starts_with('#'));

    let slack = Slack::new(webhook.as_str()).unwrap();
    let p = PayloadBuilder::new()
        .text(message.as_single_string())
        .channel(channel)
        .username("Snitch")
        .icon_emoji(":varys:")
        .build()
        .unwrap();

    slack.send(&p)
}

#[cfg(test)]
mod tests {

    use super::send_message;
    use crate::test_utils::get_test_message;

    /// Tests dispatching message. Requires configured SLACK configuration.
    #[tokio::test]
    async fn test_send_message() {
        let message = get_test_message();
        send_message(message).await.unwrap();
    }
}
