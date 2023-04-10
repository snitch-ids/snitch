use crate::dispatcher::{DispatchError, Example, Handler};
use crate::message::Message;
use lettre::transport::smtp::authentication::Credentials;
use lettre::Message as LettreMessage;
use lettre::{SmtpTransport, Transport};
use log::{debug, error};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast::Receiver;

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Email {
    pub smtp_user: String,
    pub smtp_password: String,
    pub smtp_server: String,
    pub receiver_address: String,
}

impl Example for Email {
    fn example() -> Self {
        Self {
            smtp_user: "USERNAME".to_string(),
            smtp_password: "SUPERSECUREPASSWORD".to_string(),
            smtp_server: "".to_string(),
            receiver_address: "".to_string(),
        }
    }
}

impl Handler for Email {
    fn check(&self) -> Result<(), DispatchError> {
        todo!()
    }

    fn start_handler(self, receiver: Receiver<String>) {
        let mut email_handler = EmailHandler {
            config: self,
            receiver,
        };
        tokio::spawn(async move {
            email_handler.start().await;
        });
        debug!("started email handlers");
    }
}

pub struct EmailHandler {
    pub(crate) config: Email,
    pub(crate) receiver: Receiver<String>,
}

impl EmailHandler {
    /// Dispatch an email
    async fn send(&self, message: Message<'_>) {
        let config = &self.config;
        let email = LettreMessage::builder()
            .from("Snitch <noreply@intrusion.detection>".parse().unwrap())
            .reply_to("noreply@intrusion.detection".parse().unwrap())
            .to(config.receiver_address.parse().unwrap())
            .subject("Intrusion Detected")
            .body(message.html())
            .unwrap();

        let credentials = Credentials::new(config.smtp_user.clone(), config.smtp_password.clone());

        let mailer = SmtpTransport::relay(&*config.smtp_server)
            .unwrap()
            .credentials(credentials)
            .build();

        match mailer.send(&email) {
            Ok(_) => debug!("Email sent successfully"),
            Err(e) => error!("Could not send email: {:?}", e),
        }
    }

    pub async fn start(&mut self) {
        loop {
            if let Ok(data) = self.receiver.recv().await {
                let message = Message::from_json(&data);
                self.send(message).await;
            } else {
                break;
            }
        }
    }
}

#[test]
fn test_example() {
    Email::example();
}
