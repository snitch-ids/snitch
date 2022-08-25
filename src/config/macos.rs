use crate::notifiers::Dispatcher;

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
        notifications: Dispatcher {
            enable_email: false,
            enable_telegram: true,
            enable_slack: false,
        },
        snitch_root: "/etc/snitch".to_owned(),
    }
}
