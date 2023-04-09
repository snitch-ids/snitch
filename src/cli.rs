use clap::Parser;

static DEFAULT_CONFIG: &str = "/etc/snitch/config.yaml";

/// Get notified when someone intrudes into your system or changes files.
#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
#[command(arg_required_else_help = true)]
pub struct Cli {
    /// Print a demo configuration (e.g. as a template for /etc/snitch/config.yaml)
    #[clap(long)]
    pub demo_config: bool,

    /// Use this config file
    #[clap(long, default_value = DEFAULT_CONFIG)]
    pub config: String,

    /// Use this config file
    #[clap(long)]
    pub send_test_message: bool,

    /// Initialize the database
    #[clap(short, long)]
    pub init: bool,

    /// Start scanning files
    #[clap(short, long)]
    pub scan: bool,

    /// Watch for file changes
    #[clap(short, long)]
    pub watch_files: bool,

    /// Watch authentication logs for logins
    #[clap(long)]
    pub watch_authentications: bool,

    /// Verbose mode
    #[clap(short, long)]
    pub verbose: bool,
}
