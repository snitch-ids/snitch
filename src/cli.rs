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

    /// With --init: hash the files below DIR as if it were / (when building
    /// an image). The database goes below DIR too; its paths leave DIR out.
    #[clap(long, value_name = "DIR", requires = "init")]
    pub root: Option<String>,

    /// Start scanning files
    #[clap(short, long)]
    pub scan: bool,

    /// Accept the current content of these files: store their hashes in the
    /// database (and forget the ones that don't exist). A running snitch
    /// --watch-ebpf uses them after a restart.
    #[clap(long, value_name = "PATH", num_args = 1..)]
    pub accept: Vec<String>,

    /// Watch for file changes
    #[clap(short, long)]
    pub watch_files: bool,

    /// Watch authentication logs for logins
    #[clap(long)]
    pub watch_authentications: bool,

    /// Watch the files from the database with BPF LSM programs: reports
    /// writes (re-hashed when the writer closes the file), removal, renames,
    /// hard links, permission and owner changes, and new entries in the
    /// configured directories, with the process that did it. Needs root,
    /// Linux with the BPF LSM active, and a build with the `ebpf` feature.
    #[clap(long)]
    pub watch_ebpf: bool,

    /// Verbose mode
    #[clap(short, long)]
    pub verbose: bool,
}
