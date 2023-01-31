pub mod storage;
pub mod rpc;
pub mod p2p;
pub mod core;

use fern::colors::Color;
use log::{info, error};
use p2p::P2pServer;
use rpc::getwork_server::SharedGetWorkServer;
use xelis_common::{
    prompt::{Prompt, command::{CommandManager, CommandError, Command, CommandHandler}, PromptError, argument::ArgumentManager},
    config::{VERSION, BLOCK_TIME}, globals::format_hashrate, async_handler
};
use crate::core::blockchain::{Config, Blockchain};
use std::sync::Arc;
use std::time::Duration;
use clap::Parser;
use anyhow::Result;

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
async fn main() -> Result<()> {
    let config: NodeConfig = NodeConfig::parse();
    let prompt = Prompt::new(config.debug, config.filename_log, config.disable_file_logging)?;
    info!("Xelis Blockchain running version: {}", VERSION);
    info!("----------------------------------------------");
    let blockchain = Blockchain::new(config.nested).await?;

    if let Err(e) = run_prompt(&prompt, blockchain.clone()).await {
        error!("Error while running prompt: {}", e);
    }

    blockchain.stop().await;
    Ok(())
}

async fn run_prompt(prompt: &Arc<Prompt>, blockchain: Arc<Blockchain>) -> Result<(), PromptError> {
    let mut command_manager: CommandManager<Arc<Blockchain>> = CommandManager::default();
    command_manager.set_data(Some(blockchain.clone()));
    command_manager.add_command(Command::new("list_peers", "List all peers connected", None, CommandHandler::Async(async_handler!(list_peers))));

    let p2p: Option<Arc<P2pServer>> = match blockchain.get_p2p().lock().await.as_ref() {
        Some(p2p) => Some(p2p.clone()),
        None => None
    };
    let getwork: Option<SharedGetWorkServer> = match blockchain.get_rpc().lock().await.as_ref() {
        Some(rpc) => rpc.getwork_server().clone(),
        None => None
    };
 
    let closure = || async {
        let height = blockchain.get_height();
        let (peers, best) = match &p2p {
            Some(p2p) => (p2p.get_peer_count().await, p2p.get_best_height().await),
            None => (0, height)
        };

        let miners = match &getwork {
            Some(getwork) => getwork.count_miners().await,
            None => 0
        };

        let network_hashrate = (blockchain.get_difficulty() / BLOCK_TIME) as f64;
        build_prompt_message(blockchain.get_topo_height(), height, best, network_hashrate, peers, miners)
    };

    prompt.start(Duration::from_millis(100), &closure, command_manager).await
}

fn build_prompt_message(topoheight: u64, height: u64, best_height: u64, network_hashrate: f64, peers_count: usize, miners_count: usize) -> String {
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

    let network_hashrate_str = format!(
        "{}: {}",
        Prompt::colorize_str(Color::Yellow, "Network"),
        Prompt::colorize_string(Color::Green, &format!("{}", format_hashrate(network_hashrate))),
    );
    let peers_str = format!(
        "{}: {}",
        Prompt::colorize_str(Color::Yellow, "Peers"),
        Prompt::colorize_string(Color::Green, &format!("{}", peers_count))
    );
    let miners_str = format!(
        "{}: {}",
        Prompt::colorize_str(Color::Yellow, "Miners"),
        Prompt::colorize_string(Color::Green, &format!("{}", miners_count))
    );
    format!(
        "{} | {} | {} | {} | {} | {} {} ",
        Prompt::colorize_str(Color::Blue, "XELIS"),
        height_str,
        topoheight_str,
        network_hashrate_str,
        peers_str,
        miners_str,
        Prompt::colorize_str(Color::BrightBlack, ">>")
    )
}

async fn list_peers(blockchain: Arc<Blockchain>, _: ArgumentManager) -> Result<(), CommandError> {
    match blockchain.get_p2p().lock().await.as_ref() {
        Some(p2p) => {
            let peer_list = p2p.get_peer_list().read().await;
            for peer in peer_list.get_peers().values() {
                info!("{}", peer);
            }
            info!("Total peer(s) count: {}", peer_list.size());
        },
        None => {
            error!("No P2p server running!");
        }
    };
    Ok(())
}