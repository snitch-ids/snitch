use chatterbox::dispatcher::{Example, Sender};

use super::Config;

pub fn get_config() -> Config {
    Config {
        directories: vec![
            "/System".to_owned(),
            "/Users".to_owned(),
            "/sbin".to_owned(),
            "/opt".to_owned(),
        ],
        authentication_logs: None,
        sender: Sender::example(),
        snitch_root: "/etc/snitch".to_owned(),
    }
}
