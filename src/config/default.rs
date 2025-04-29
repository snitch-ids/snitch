use chatterbox::dispatcher::{Example, Sender};

use super::Config;

pub fn get_config() -> Config {
    Config {
        directories: vec![
            "/bin".to_owned(),
            "/sbin".to_owned(),
            "/boot".to_owned(),
            "/root".to_owned(),
            "/usr".to_owned(),
            "/lib".to_owned(),
            "/etc".to_owned(),
        ],
        sender: Sender::example(),
        authentication_logs: Some("/var/log/auth.log".to_owned()),
        snitch_root: "/etc/snitch".to_owned(),
    }
}
