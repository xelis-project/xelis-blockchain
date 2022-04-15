mod globals;
mod config;
mod crypto;
mod wallet;
mod core;
mod p2p;

use crate::core::blockchain::Blockchain;
use crate::core::prompt::command::CommandManager;
use crate::core::prompt::prompt::{Prompt, PromptError};
use crate::core::prompt::argument::*;
use crate::core::prompt::command::{Command, CommandError};
use crate::config::VERSION;
use fern::colors::Color;
use log::{info, error};
use std::thread;
use argh::FromArgs;
use std::time::Duration;
use std::sync::Arc;

#[derive(FromArgs)]
/// Xelis Blockchain daemon
struct NodeConfig {
    /// optional node tag
    #[argh(option)]
    tag: Option<String>,
    /// bind address for p2p
    #[argh(option, default = "config::DEFAULT_BIND_ADDRESS.to_string()")]
    bind_address: String,
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

    if config.mining {
        let blockchain = blockchain.clone();
        tokio::spawn(async move {
            let key = blockchain.get_dev_address().clone();
            loop {
                if let Err(e) = blockchain.mine_block(&key).await {
                    error!("Error while mining block: {}", e);
                }
            }
        });
    }

    if let Err(e) = run_prompt(prompt, blockchain).await { // block main thread
        error!("Error while running prompt: {}", e);
    }
}

fn build_prompt_message(height: u64, peers_count: usize) -> String {
    let height_str = format!(
        "{}: {}",
        Prompt::colorize_str(Color::Yellow, "Height"),
        Prompt::colorize_string(Color::Green, &format!("{}", height)) // TODO Color based on height / peer
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

async fn run_prompt(prompt: Arc<Prompt>, blockchain: Arc<Blockchain>) -> Result<(), PromptError> {
    prompt.update_prompt(Some(build_prompt_message(0, 0)))?;
    let mut display_height = 0;
    let mut display_peers = 0;
    loop {
        let height = blockchain.get_height();
        let peers_count = match blockchain.get_p2p().lock().await.as_ref() {
            Some(p2p) => p2p.get_peer_count().await,
            None => 0
        };

        if display_height != height || display_peers != peers_count {
            display_height = height;
            display_peers = peers_count;
            prompt.update_prompt(Some(build_prompt_message(height, peers_count)))?;
        }

        /*if let Some(cmd) = prompt.read_command()? {
            println!();
            debug!("calling command '{}'", cmd);
            match cmd.as_ref() {
                "exit" => break,
                "validity" => {
                    if let Err(e) = blockchain.check_validity().await {
                        error!("Blockchain is not valid: {}", e);
                    } else {
                        info!("Blockchain is valid");
                    }
                },
                "mine" => {
                    let key = blockchain.get_dev_address().clone();
                    if let Err(e) = blockchain.mine_block(&key).await {
                        error!("Error while mining block: {}", e);
                    }
                },
                "peer_list" => {
                    match blockchain.get_p2p().lock().await.as_ref() {
                        Some(p2p) => {
                            p2p.get_peer_list().lock().await.get_peers().iter().for_each(|(_,peer)| {
                                info!("{}", peer);
                            });
                        }
                        None => {
                            error!("No p2p instance found");
                        }
                    };
                }
                cmd => info!("You said: {}", cmd)
            };
        }*/
        thread::sleep(Duration::from_millis(100)); // update every 100ms
    }

    Ok(())
}