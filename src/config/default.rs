use crate::notifiers::Dispatcher;

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
        authentication_logs: Some("/var/log/auth.log".to_owned()),
        notifications: Dispatcher {
            enable_email: false,
            enable_telegram: true,
            enable_slack: false,
        },
        snitch_root: "/etc/snitch".to_owned(),
    }
}
