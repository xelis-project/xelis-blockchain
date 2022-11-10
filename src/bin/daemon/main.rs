use xelis_blockchain::core::error::BlockchainError;
use xelis_blockchain::core::prompt::command::{Command, CommandError};
use xelis_blockchain::core::prompt::prompt::{Prompt, PromptError};
use xelis_blockchain::core::prompt::command::CommandManager;
use xelis_blockchain::core::blockchain::{Blockchain, Config};
use xelis_blockchain::core::prompt::argument::*;
use xelis_blockchain::config::VERSION;
use fern::colors::Color;
use log::{info, error};
use std::sync::Arc;
use clap::Parser;

#[derive(Parser)]
#[clap(version = VERSION, about = "XELIS Daemon")]
pub struct NodeConfig {
    #[structopt(flatten)]
    nested: Config,
    /// Enable the debug mode
    #[clap(short, long)]
    debug: bool,
    /// Disable the log file
    #[clap(short = 'f', long)]
    disable_file_logging: bool,
    /// Log filename
    #[clap(short = 'n', long, default_value_t = String::from("xelis.log"))]
    filename_log: String
}

#[tokio::main]
async fn main() -> Result<(), BlockchainError> {
    let config: NodeConfig = NodeConfig::parse();
    let command_manager = create_command_manager();
    let prompt = Prompt::new(config.debug, config.filename_log, config.disable_file_logging, command_manager)?;
    info!("Xelis Blockchain running version: {}", VERSION);
    info!("----------------------------------------------");
    let blockchain = Blockchain::new(config.nested).await?;

    tokio::select! {
        Err(e) = run_prompt(&prompt, blockchain.clone()) => {
            error!("Error while running prompt: {}", e);
        },
        res = tokio::signal::ctrl_c() => {
            if let Err(e) = res {
                error!("Error received on CTRL+C: {}", e);
            } else {
                info!("CTRL+C received, exiting...");
            }
        }
    }
    blockchain.stop().await;
    Ok(())
}

async fn run_prompt(prompt: &Arc<Prompt>, blockchain: Arc<Blockchain>) -> Result<(), PromptError> {
    let closure = || async {
        let height = blockchain.get_height();
        let (peers, best) = match blockchain.get_p2p().lock().await.as_ref() {
            Some(p2p) => (p2p.get_peer_count().await, p2p.get_best_height().await),
            None => (0, height)
        };
        build_prompt_message(blockchain.get_topo_height(), height, best, peers)
    };

    prompt.handle_commands(&closure).await
}

fn build_prompt_message(topoheight: u64, height: u64, best_height: u64, peers_count: usize) -> String {
    let height_str = format!(
        "{}: {}/{}",
        Prompt::colorize_str(Color::Yellow, "Height"),
        Prompt::colorize_string(Color::Green, &format!("{}", height)), // TODO Color based on height / peer
        Prompt::colorize_string(Color::Green, &format!("{}", best_height))
    );
    let topoheight_str = format!(
        "{}: {}",
        Prompt::colorize_str(Color::Yellow, "TopoHeight"),
        Prompt::colorize_string(Color::Green, &format!("{}", topoheight)),
    );
    let peers_str = format!(
        "{}: {}",
        Prompt::colorize_str(Color::Yellow, "Peers"),
        Prompt::colorize_string(Color::Green, &format!("{}", peers_count))
    );
    format!(
        "{} | {} | {} | {} {} ",
        Prompt::colorize_str(Color::Blue, "XELIS"),
        height_str,
        topoheight_str,
        peers_str,
        Prompt::colorize_str(Color::BrightBlack, ">>")
    )
}

fn help(manager: &CommandManager, mut args: ArgumentManager) -> Result<(), CommandError> {
    if args.has_argument("command") {
        let arg_value = args.get_value("command")?.to_string_value()?;
        let cmd = manager.get_command(&arg_value).ok_or(CommandError::CommandNotFound)?;
        manager.message(&format!("Usage: {}", cmd.get_usage()));
    } else {
        manager.message("Available commands:");
        for cmd in manager.get_commands() {
            manager.message(&format!("- {}: {}", cmd.get_name(), cmd.get_description()));
        }
    }
    Ok(())
}
 
fn create_command_manager() -> CommandManager {
    let mut manager = CommandManager::new();
    manager.add_command(Command::new("help", "Show this help", Some(Arg::new("command", ArgType::String)), help));
    manager
}
