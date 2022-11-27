use super::Config;
use multi_dispatcher::dispatcher::{Example, Sender};

pub fn get_config() -> Config {
    Config {
        directories: vec!["C:/Windows".to_owned()],
        authentication_logs: None,
        sender: Sender::example(),
        snitch_root: "C:/ProgramData/snitch".to_owned(),
    }
}
