use xelis_blockchain::core::prompt::command::{Command, CommandError};
use xelis_blockchain::core::prompt::prompt::{Prompt, PromptError};
use xelis_blockchain::core::prompt::command::CommandManager;
use xelis_blockchain::core::blockchain::Blockchain;
use xelis_blockchain::core::prompt::argument::*;
use xelis_blockchain::config::VERSION;
use fern::colors::Color;
use log::{info, error};
use argh::FromArgs;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

#[derive(FromArgs)]
/// Xelis Blockchain daemon
struct NodeConfig {
    /// optional node tag
    #[argh(option)]
    tag: Option<String>,
    /// bind address for p2p
    #[argh(option, default = "xelis_blockchain::config::DEFAULT_BIND_ADDRESS.to_string()")]
    bind_address: String,
    /// priority nodes
    #[argh(option)]
    priority_nodes: Vec<String>,
    /// enable debug logging
    #[argh(switch)]
    debug: bool,
    /// enable mining on this node
    #[argh(switch)]
    mining: bool,
    /// disable file logging
    #[argh(switch)]
    disable_file_logging: bool
}

#[tokio::main]
async fn main() {
    let config: NodeConfig = argh::from_env();
    let command_manager = create_command_manager();
    let prompt = match Prompt::new(config.debug, config.disable_file_logging, command_manager) {
        Ok(prompt) => prompt,
        Err(e) => {
            println!("Error while initializing prompt: {}", e);
            return
        }
    };
    info!("Xelis Blockchain running version: {}", VERSION);
    info!("----------------------------------------------");
    let blockchain = match Blockchain::new(config.tag, config.bind_address).await {
        Ok(blockchain) => blockchain,
        Err(e) => {
            error!("Couldn't create blockchain: {}", e);
            return;
        }
    };

    if let Some(p2p) = blockchain.get_p2p().lock().await.as_ref() {
        for addr in config.priority_nodes {
            let addr: SocketAddr = match addr.parse() {
                Ok(addr) => addr,
                Err(e) => {
                    error!("Error while parsing priority node: {}", e);
                    continue;
                }
            };
            p2p.try_to_connect_to_peer(addr, true);
        }
    }

    if config.mining {
        let blockchain = blockchain.clone();
        tokio::spawn(async move { // TODO: move in another thread instead of tokio
            let key = blockchain.get_dev_address().clone();
            loop {
                if let Err(e) = blockchain.mine_block(&key).await {
                    error!("Error while mining block: {}", e);
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });
    }

    if let Err(e) = run_prompt(prompt, blockchain.clone()).await {
        error!("Error while running prompt: {}", e);
    }
    let p2p = blockchain.get_p2p().lock().await;
    if let Some(p2p) = p2p.as_ref() {
        p2p.stop().await;
    }
}

async fn run_prompt(prompt: Arc<Prompt>, blockchain: Arc<Blockchain>) -> Result<(), PromptError> {
    let closure = || async {
        let height = blockchain.get_height();
        let (peers, best) = match blockchain.get_p2p().lock().await.as_ref() {
            Some(p2p) => (p2p.get_peer_count().await, p2p.get_best_height().await),
            None => (0, height)
        };
        build_prompt_message(height, best, peers)
    };

    prompt.handle_commands(&closure).await
}

fn build_prompt_message(height: u64, best_height: u64, peers_count: usize) -> String {
    let height_str = format!(
        "{}: {}/{}",
        Prompt::colorize_str(Color::Yellow, "Height"),
        Prompt::colorize_string(Color::Green, &format!("{}", height)), // TODO Color based on height / peer
        Prompt::colorize_string(Color::Green, &format!("{}", best_height))
    );
    let peers_str = format!(
        "{}: {}",
        Prompt::colorize_str(Color::Yellow, "Peers"),
        Prompt::colorize_string(Color::Green, &format!("{}", peers_count))
    );
    format!(
        "{} | {} | {} {} ",
        Prompt::colorize_str(Color::Blue, "XELIS"),
        height_str,
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
