use super::Config;
use multi_dispatcher::dispatcher::Sender;

pub fn get_config() -> Config {
    Config {
        directories: vec!["/Windows".to_owned()],
        authentication_logs: None,
        sender: Sender::demo_sender(),
        snitch_root: "/etc/snitch".to_owned(),
    }
}
