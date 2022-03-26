use std::path::Path;
use std::str::from_utf8;
use std::string::String;
use std::time::Duration;

use clap::lazy_static::lazy_static;
use regex::{Captures, Regex};
use tokio::fs::File;
use tokio::io::SeekFrom;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::time;

use crate::notifiers::Dispatcher;

pub async fn watch_authentication_logs(path: &Path) {
    let mut file = File::open(path).await.unwrap();
    let mut interval = time::interval(Duration::from_millis(1000));
    let mut contents = vec![];
    let mut position = file.read_to_end(&mut contents).await.unwrap();

    loop {
        contents.truncate(0);
        file.seek(SeekFrom::Start(position as u64)).await;
        position += file.read_to_end(&mut contents).await.unwrap();

        let contents_str = from_utf8(&contents).unwrap();
        let mut logins = parse_logins(contents_str);

        info!("logins {:?}", logins);
        for login in logins.iter_mut() {
            login.dispatch();
        }

        interval.tick().await;
    }
}

impl Dispatcher for Login {
    fn message(&mut self) -> String {
        format!(
            "<i>Nitro</i>\nNew login from IP <code>{}</code> on <b>{}</b>\n{}",
             self.ip, self.hostname, self.datetime
        )
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
    let test_file = Path::new("test/auth.log");
    // watch_authentication_logs(test_file).await;
}
