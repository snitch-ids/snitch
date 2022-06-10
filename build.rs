use std::fs;
use std::path::Path;
use std::process::exit;

static DEFAULT_CONFIG_PATH: &str = "/etc/snitch/";

/// Print debugging output to console as warning.
macro_rules! print_create_failure {
    ($($tokens: tt)*) => {
        println!("cargo:warning=Could not create {} - {}", DEFAULT_CONFIG_PATH, format!($($tokens)*))
    }
}

/// Attempts to create /etc/snitch/config.yaml with a default configuration.
fn main() {
    fs::create_dir(Path::new(DEFAULT_CONFIG_PATH)).unwrap_or_else(|error| {
        let kind = error.kind();
        print_create_failure!("{}", kind);
        exit(0);
    });
    let out_dir = Path::new(DEFAULT_CONFIG_PATH);
    let dest_path = Path::new(&out_dir).join("config.yaml");
    fs::write(
        &dest_path,
        "---
directories:
  - /bin
  - /sbin
  - /boot
  - /root
  - /usr
  - /lib
  - /etc
notifications:
  enable_email: false
  enable_telegram: true
authentication_logs: /var/log/auth.log
",
    )
    .unwrap();
    println!("cargo:rerun-if-changed=build.rs");
}
