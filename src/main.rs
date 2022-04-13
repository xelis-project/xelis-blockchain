mod globals;
mod config;
mod crypto;
mod wallet;
mod core;
mod p2p;

use crate::core::blockchain::Blockchain;
use crate::core::prompt::{Prompt, PromptError};
use crate::config::VERSION;
use fern::colors::Color;
use log::{debug, info, error};
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

fn main() {
    let config: NodeConfig = argh::from_env();
    let prompt = match Prompt::new(config.debug, config.disable_file_logging) {
        Ok(prompt) => prompt,
        Err(e) => {
            println!("Error while initializing prompt: {}", e);
            return
        }
    };
    info!("Xelis Blockchain running version: {}", VERSION);
    info!("----------------------------------------------");
    let blockchain = match Blockchain::new(config.tag, config.bind_address) {
        Ok(blockchain) => blockchain,
        Err(e) => {
            error!("Couldn't create blockchain: {}", e);
            return;
        }
    };

    if config.mining {
        let blockchain = blockchain.clone();
        thread::spawn(move || {
            let key = blockchain.get_dev_address().clone();
            loop {
                if let Err(e) = blockchain.mine_block(&key) {
                    error!("Error while mining block: {}", e);
                }
            }
        });
    }

    if let Err(e) = run_prompt(prompt, blockchain) { // block main thread
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

fn run_prompt(prompt: Arc<Prompt>, blockchain: Arc<Blockchain>) -> Result<(), PromptError> {
    prompt.update_prompt(Some(build_prompt_message(0, 0)))?;
    let mut display_height = 0;
    let mut display_peers = 0;
    loop {
        let height = blockchain.get_height();
        let peers_count = match blockchain.get_p2p().lock()?.as_ref() {
            Some(p2p) => p2p.get_peer_count(),
            None => 0
        };
        if display_height != height || display_peers != peers_count {
            display_height = height;
            display_peers = peers_count;
            prompt.update_prompt(Some(build_prompt_message(height, peers_count)))?;
        }

        if let Some(cmd) = prompt.read_command()? {
            println!();
            debug!("calling command '{}'", cmd);
            match cmd.as_ref() {
                "exit" => break,
                "validity" => {
                    if let Err(e) = blockchain.check_validity() {
                        error!("Blockchain is not valid: {}", e);
                    } else {
                        info!("Blockchain is valid");
                    }
                },
                "peer_list" => {
                    match blockchain.get_p2p().lock()?.as_ref() {
                        Some(p2p) => {
                            p2p.get_peer_list().lock()?.get_peers().iter().for_each(|(_,peer)| {
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
        }
        thread::sleep(Duration::from_millis(100)); // update every 100ms
    }

    Ok(())
}