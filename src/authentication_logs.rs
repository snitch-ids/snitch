use std::str::from_utf8;
use std::string::String;
use std::time::Duration;

use lazy_static::lazy_static;
use regex::{Captures, Regex};
use tokio::fs::File;
use tokio::io::SeekFrom;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::time;

use crate::config::Config;
use multi_dispatcher::message::{Dispatcher, Message, Notification};

static INTERVAL: u64 = 1000;

#[derive(Debug)]
pub enum WatchLogsError {
    NoLogFile,
}

/// Watch authentication logs and dispatch a [Notification](notifiers::Notification) if a login was registered.
pub async fn watch_authentication_logs(
    dispatcher: &Dispatcher,
    config: &Config,
) -> Result<(), WatchLogsError> {
    info!("start watching authentication logs");
    let filename = match config.authentication_logs.as_deref() {
        None => return Err(WatchLogsError::NoLogFile),
        Some(v) => v,
    };
    let mut file = File::open(filename).await.unwrap();
    let mut interval = time::interval(Duration::from_millis(INTERVAL));
    let mut contents = vec![];
    let mut position = file.read_to_end(&mut contents).await.unwrap();

    loop {
        contents.truncate(0);
        file.seek(SeekFrom::Start(position as u64))
            .await
            .expect("Failed seeking log position!");
        position += file.read_to_end(&mut contents).await.unwrap();

        let contents_str = from_utf8(&contents).unwrap();

        let logins = find_logins(contents_str);
        for login in logins.iter() {
            info!("logins {:?}", login);
            dispatcher.dispatch(login);
        }

        let root_elevations = find_root_elevations(contents_str);
        for root_elecation in root_elevations.iter() {
            info!("root elevation {:?}", root_elecation);
            dispatcher.dispatch(root_elecation);
        }

        interval.tick().await;
    }
}

#[derive(Debug)]
struct RootElevation {
    username: String,
    datetime: String,
    hostname: String,
}

impl RootElevation {
    fn from_capture(cap: &Captures) -> RootElevation {
        let username = cap["username"].to_owned();
        let datetime = cap["datetime"].to_owned();
        let hostname = cap["hostname"].to_owned();
        RootElevation {
            username,
            datetime,
            hostname,
        }
    }
}

impl Notification for RootElevation {
    fn message(&self) -> Message {
        let content = format!(
            "User <b>{}</b> just become root on <code>{}</code>\n{}",
            self.username, self.hostname, self.datetime
        );
        Message::new_now("Root elevation", content)
    }
}

#[derive(Debug)]
struct Login {
    username: String,
    ip: String,
    datetime: String,
    hostname: String,
    method: String,
}

impl Login {
    fn from_capture(cap: &Captures) -> Login {
        let username = cap["username"].to_owned();
        let ip = cap["ipaddress"].to_owned();
        let datetime = cap["datetime"].to_owned();
        let hostname = cap["hostname"].to_owned();
        let method = cap["method"].to_owned();
        Login {
            username,
            ip,
            datetime,
            hostname,
            method,
        }
    }
}

impl Notification for Login {
    fn message(&self) -> Message {
        let content = format!(
            "New login by <b>{}</b> from IP <code>{}</code> on <b>{}</b>\nmethod: {}\n{}",
            self.username, self.ip, self.hostname, self.method, self.datetime
        );
        Message::new_now("Login", content)
    }
}

/// Finds logins in authentication logs
fn find_root_elevations(contents: &str) -> Vec<RootElevation> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"(?P<datetime>\D{3,4} \d{1,2} \d{1,2}:\d{2}:\d{2}) (?P<hostname>.+) sudo: pam_unix\(sudo:session\): session opened for user root by (?P<username>.*)").unwrap();
    }
    RE.captures_iter(contents)
        .map(|cap| RootElevation::from_capture(&cap))
        .collect()
}

/// Finds logins in authentication logs
fn find_logins(contents: &str) -> Vec<Login> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"(?P<datetime>\D{3,4} \d{1,2} \d{1,2}:\d{2}:\d{2}) (?P<hostname>.+) (?P<process>sshd\[\d+\]):.* Accepted (?P<method>\w+) for (?P<username>.*) from (?P<ipaddress>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}) port (?P<port>\d+)").unwrap();
    }
    RE.captures_iter(contents)
        .map(|cap| Login::from_capture(&cap))
        .collect()
}

#[tokio::test]
async fn parse_test() {
    use std::fs;
    use std::path::Path;

    let test_file = Path::new("test/auth.log");
    let data = fs::read_to_string(test_file).unwrap();
    let logins = find_logins(&data);
    assert_eq!(logins.len(), 2);

    let root_elecations = find_root_elevations(&data);
    assert_eq!(root_elecations.len(), 1);
}
