use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "nas-analyzer", version, about = "NAS Storage Analyzer")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the API server, scheduler, sampler and worker supervisor.
    Serve {
        #[arg(long)]
        config: String,
    },
    /// Scan worker subprocess. Started by the serve supervisor, not by users.
    Worker {
        #[arg(long)]
        config: Option<String>,
        #[arg(long)]
        job_id: String,
    },
    /// Validate a deployment configuration file and exit.
    ConfigCheck {
        #[arg(long)]
        config: String,
    },
    /// HTTP health probe for container healthchecks.
    Healthcheck {
        #[arg(long)]
        url: String,
    },
    /// Administrative commands against a local data directory.
    Admin {
        #[command(subcommand)]
        action: AdminAction,
    },
    /// Create a configuration backup archive.
    Backup {
        #[arg(long)]
        data_dir: String,
        #[arg(long)]
        output: String,
    },
    /// Restore a configuration backup archive.
    Restore {
        #[arg(long)]
        data_dir: String,
        #[arg(long)]
        input: String,
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum AdminAction {
    /// Reset an admin password (interactive prompt; revokes sessions).
    ResetPassword {
        #[arg(long)]
        data_dir: String,
        #[arg(long)]
        username: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::ConfigCheck { config } => nas_analyzer::cli::config_check(&config),
        Command::Healthcheck { url } => nas_analyzer::cli::healthcheck(&url),
        Command::Serve { config } => nas_analyzer::cli::serve(&config),
        Command::Worker { config, job_id } => nas_analyzer::cli::worker(config.as_deref(), &job_id),
        Command::Admin {
            action: AdminAction::ResetPassword { data_dir, username },
        } => nas_analyzer::cli::admin_reset_password(&data_dir, &username),
        Command::Backup { data_dir, output } => nas_analyzer::cli::backup(&data_dir, &output),
        Command::Restore {
            data_dir,
            input,
            dry_run,
        } => nas_analyzer::cli::restore(&data_dir, &input, dry_run),
    }
}
