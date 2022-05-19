use clap::Parser;

/// Get notified when someone intrudes into your system.
#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
pub struct Cli {
    /// initialize the database
    #[clap(short, long)]
    pub init: bool,

    /// Start scanning files
    #[clap(short, long)]
    pub scan: bool,

    /// Start scanning authentication
    #[clap(short, long)]
    pub watch_authentication: bool,

    /// print a demo configuration (e.g. as a template for /etc/nitro/config.yaml)
    #[clap(long)]
    pub demo_config: bool,
}
