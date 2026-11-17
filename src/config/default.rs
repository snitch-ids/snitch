use chatterbox::dispatcher::{Example, Sender};

use super::Config;

pub fn get_config() -> Config {
    Config {
        // --demo-config leaves out the ones that don't exist or are
        // symlinks (/bin -> usr/bin on most distributions). Only root's ssh
        // keys from /root: the rest changes all the time (shell history).
        directories: vec![
            "/etc".to_owned(),
            "/usr".to_owned(),
            "/boot".to_owned(),
            "/bin".to_owned(),
            "/sbin".to_owned(),
            "/lib".to_owned(),
            "/root/.ssh".to_owned(),
        ],
        sender: Sender::example(),
        authentication_logs: None,
        snitch_root: "/etc/snitch".to_owned(),
        url: Config::default_url(),
        token: "SDFOIJSDFOIJSDFOIJ".to_string(),
        heartbeat_interval: Config::default_heartbeat_interval(),
        origin: None,
    }
}
