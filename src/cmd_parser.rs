use clap::Command;

pub enum Mode {
    Setup,
    Run,
}

pub fn parse_mode() -> Mode {
    let matches = Command::new("Pass Manager")
        .version("1.0")
        .author("Standby-Coder <ckreddy573@gmail.com>")
        .about("Manages your passwords securely")
        .subcommand(Command::new("--setup").about("Sets up the password manager"))
        .subcommand(Command::new("--run").about("Runs the password manager"))
        .get_matches();

    match matches.subcommand() {
        Some(("--setup", _)) => Mode::Setup,
        Some(("--run", _)) => Mode::Run,
        _ => {
            // If no subcommand, print help and exit gracefully
            eprintln!("You must specify either 'setup' or 'run' subcommand.");
            std::process::exit(1);
        }
    }
}
