use std::env;

use super::Message;
use lettre::transport::smtp::authentication::Credentials;
use lettre::Message as LettreMessage;
use lettre::{SmtpTransport, Transport};

/// Dispatch an email
pub async fn send_message(message: Message) {
    let smtp_user = env::var("SMTP_USER").expect("environment variable SMTP_USER not set");
    let smtp_password =
        env::var("SMTP_PASSWORD").expect("environment variable SMTP_PASSWORD not set");
    let smtp_server = env::var("SMTP_SERVER").expect("environment variable SMTP_SERVER not set");

    let email = LettreMessage::builder()
        .from("Snitch <noreply@intrusion.detection>".parse().unwrap())
        .reply_to("noreply@intrusion.detection".parse().unwrap())
        .to("marius.kriegerowski@gmail.com".parse().unwrap())
        .subject("Intrusion Detected")
        .body(message.as_single_string())
        .unwrap();

    let credentials = Credentials::new(smtp_user, smtp_password);

    let mailer = SmtpTransport::relay(&*smtp_server)
        .unwrap()
        .credentials(credentials)
        .build();

    match mailer.send(&email) {
        Ok(_) => debug!("Email sent successfully"),
        Err(e) => warn!("Could not send email: {:?}", e),
    }
}
