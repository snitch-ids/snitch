use super::Config;
use chatterbox::dispatcher::{Example, Sender};

pub fn get_config() -> Config {
    Config {
        directories: vec!["C:/Windows".to_owned()],
        authentication_logs: None,
        sender: Sender::example(),
        snitch_root: "C:/ProgramData/snitch".to_owned(),
    }
}
