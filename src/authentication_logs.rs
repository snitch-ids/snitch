use std::str::from_utf8;
use std::string::String;
use std::time::Duration;

use clap::lazy_static::lazy_static;
use regex::{Captures, Regex};
use tokio::fs::File;
use tokio::io::SeekFrom;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::time;

use crate::config::Config;
use crate::notifiers::{Dispatcher, Notification};

static INTERVAL: u64 = 1000;

/// Watch authentication logs and dispatch a [Notification](notifiers::Notifaction) if a login was registered.
pub async fn watch_authentication_logs(dispatcher: &Dispatcher, config: &Config) {
    info!("start watching authentication logs");
    let mut file = File::open(config.authentication_logs.clone())
        .await
        .unwrap();
    let mut interval = time::interval(Duration::from_millis(INTERVAL));
    let mut contents = vec![];
    let mut position = file.read_to_end(&mut contents).await.unwrap();

    loop {
        contents.truncate(0);
        file.seek(SeekFrom::Start(position as u64)).await;
        position += file.read_to_end(&mut contents).await.unwrap();

        let contents_str = from_utf8(&contents).unwrap();
        let logins = parse_logins(contents_str);

        for login in logins.iter() {
            info!("logins {:?}", login);
            dispatcher.dispatch(login);
        }

        interval.tick().await;
    }
}

#[derive(Debug)]
struct Login {
    ip: String,
    datetime: String,
    hostname: String,
}

impl Login {
    fn from_capture(cap: &Captures) -> Login {
        let ip = cap["ipaddress"].to_owned();
        let datetime = cap["datetime"].to_owned();
        let hostname = cap["hostname"].to_owned();
        Login {
            ip,
            datetime,
            hostname,
        }
    }
}

impl Notification for Login {
    fn message(&self) -> String {
        format!(
            "New login from IP <code>{}</code> on <b>{}</b>\n{}",
            self.ip, self.hostname, self.datetime
        )
        .to_string()
    }
}

/// Parse a line in the authentication logs into a vector of [Login](Login) entries.
fn parse_logins(contents: &str) -> Vec<Login> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"(?P<datetime>\D{3,4} \d{1,2} \d{1,2}:\d{2}:\d{2}) (?P<hostname>.+) (?P<process>sshd\[\d+\]):.* Accepted publickey for (?P<username>.*) from (?P<ipaddress>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}) port (?P<port>\d+)").unwrap();
    }
    let logins = RE
        .captures_iter(contents)
        .map(|cap| Login::from_capture(&cap))
        .collect();
    logins
}

#[tokio::test]
async fn parse_test() {
    use std::path::Path;
    let _test_file = Path::new("test/auth.log");
    // watch_authentication_logs(test_file).await;
}
