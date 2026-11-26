use clap::Parser;

mod paired;

#[derive(Parser)]
#[command(about = "Send files between two paired devices over your Link relay")]
struct Cli {
    #[command(subcommand)]
    command: paired::Command,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    Cli::parse().command.run().await
}
