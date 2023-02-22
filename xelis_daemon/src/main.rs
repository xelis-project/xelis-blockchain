pub mod storage;
pub mod rpc;
pub mod p2p;
pub mod core;

use fern::colors::Color;
use log::{info, error};
use p2p::P2pServer;
use rpc::{getwork_server::SharedGetWorkServer, rpc::get_block_response_for_hash};
use xelis_common::{
    prompt::{Prompt, command::{CommandManager, CommandError, Command, CommandHandler}, PromptError, argument::{ArgumentManager, Arg, ArgType}},
    config::{VERSION, BLOCK_TIME}, globals::format_hashrate, async_handler, crypto::address::Address
};
use crate::core::blockchain::{Config, Blockchain};
use std::sync::Arc;
use std::time::Duration;
use clap::Parser;
use anyhow::{Result, Context};

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
    command_manager.add_command(Command::new("list_assets", "List all assets registered on chain", None, CommandHandler::Async(async_handler!(list_assets))));
    command_manager.add_command(Command::with_required_arguments("show_balance", "Show balance of an address", vec![Arg::new("address", ArgType::String), Arg::new("asset", ArgType::Hash)], Some(Arg::new("history", ArgType::Number)), CommandHandler::Async(async_handler!(show_balance))));
    command_manager.add_command(Command::with_required_arguments("print_block", "Print block in json format", vec![Arg::new("hash", ArgType::Hash)], None, CommandHandler::Async(async_handler!(print_block))));
    command_manager.add_command(Command::new("top_block", "Print top block", None, CommandHandler::Async(async_handler!(top_block))));
    command_manager.add_command(Command::with_required_arguments("pop_blocks", "Delete last N blocks", vec![Arg::new("amount", ArgType::Number)], None, CommandHandler::Async(async_handler!(pop_blocks))));

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
            Some(p2p) => (p2p.get_peer_count().await, p2p.get_best_topoheight().await),
            None => (0, height)
        };

        let miners = match &getwork {
            Some(getwork) => getwork.count_miners().await,
            None => 0
        };

        let mempool = {
            let mempool = blockchain.get_mempool().read().await;
            mempool.size()
        };

        let network_hashrate = (blockchain.get_difficulty() / BLOCK_TIME) as f64;
        build_prompt_message(blockchain.get_topo_height(), best, network_hashrate, peers, miners, mempool)
    };

    prompt.start(Duration::from_millis(100), &closure, command_manager).await
}

fn build_prompt_message(topoheight: u64, best_topoheight: u64, network_hashrate: f64, peers_count: usize, miners_count: usize, mempool: usize) -> String {
    let topoheight_str = format!(
        "{}: {}/{}",
        Prompt::colorize_str(Color::Yellow, "TopoHeight"),
        Prompt::colorize_string(Color::Green, &format!("{}", topoheight)),
        Prompt::colorize_string(Color::Green, &format!("{}", best_topoheight))
    );
    let network_hashrate_str = format!(
        "{}: {}",
        Prompt::colorize_str(Color::Yellow, "Network"),
        Prompt::colorize_string(Color::Green, &format!("{}", format_hashrate(network_hashrate))),
    );
    let mempool_str = format!(
        "{}: {}",
        Prompt::colorize_str(Color::Yellow, "Mempool"),
        Prompt::colorize_string(Color::Green, &format!("{}", mempool))
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
        topoheight_str,
        network_hashrate_str,
        mempool_str,
        peers_str,
        miners_str,
        Prompt::colorize_str(Color::BrightBlack, ">>")
    )
}

async fn list_peers(manager: &CommandManager<Arc<Blockchain>>, _: ArgumentManager) -> Result<(), CommandError> {
    let blockchain = manager.get_data()?;
    match blockchain.get_p2p().lock().await.as_ref() {
        Some(p2p) => {
            let peer_list = p2p.get_peer_list().read().await;
            for peer in peer_list.get_peers().values() {
                manager.message(format!("{}", peer));
            }
            manager.message(format!("Total peer(s) count: {}", peer_list.size()));
        },
        None => {
            manager.message("No P2p server running!");
        }
    };
    Ok(())
}

async fn list_assets(manager: &CommandManager<Arc<Blockchain>>, _: ArgumentManager) -> Result<(), CommandError> {
    let blockchain = manager.get_data()?;
    let storage = blockchain.get_storage().read().await;
    let assets = storage.get_assets().await.context("Error while retrieving assets")?;
    manager.message(format!("Registered assets ({}):", assets.len()));
    for asset in assets {
        manager.message(format!("- {}", asset));
    }
    Ok(())
}

async fn show_balance(manager: &CommandManager<Arc<Blockchain>>, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let address = arguments.get_value("address")?.to_string_value()?;
    let asset = arguments.get_value("asset")?.to_hash()?;
    let mut history = if arguments.has_argument("history") {
        let value = arguments.get_value("history")?.to_number()?;
        if value == 0 {
            return Err(CommandError::InvalidArgument("history must be a positive number".into()));
        }
        value
    } else {
        1
    };

    let address = Address::from_string(&address)?;
    let key = address.to_public_key();

    let blockchain = manager.get_data()?;
    let storage = blockchain.get_storage().read().await;
    let (mut topo, mut version) = storage.get_last_balance(&key, &asset).await.context("Error while retrieving last balance")?;
    loop {
        history -= 1;
        manager.message(format!("Balance found at topoheight {}: {}", topo, version.get_balance()));

        if history == 0 || topo == 0 {
            break;
        }

        if let Some(previous) = version.get_previous_topoheight() {
            version = storage.get_balance_at_exact_topoheight(&key, &asset, previous).await.context("Error while retrieving history balance")?;
            topo = previous;
        } else {
            break;
        }
    }

    Ok(())
}

async fn print_block(manager: &CommandManager<Arc<Blockchain>>, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let blockchain = manager.get_data()?;
    let storage = blockchain.get_storage().read().await;
    let hash = arguments.get_value("hash")?.to_hash()?;
    let response = get_block_response_for_hash(blockchain, &storage, hash, false).await.context("Error while building block response")?;
    manager.message(format!("{}", serde_json::to_string_pretty(&response).context("Error while serializing")?));

    Ok(())
}

async fn top_block(manager: &CommandManager<Arc<Blockchain>>, _: ArgumentManager) -> Result<(), CommandError> {
    let blockchain = manager.get_data()?;
    let storage = blockchain.get_storage().read().await;
    let hash = blockchain.get_top_block_hash().await.context("Error on top block hash")?;
    let response = get_block_response_for_hash(blockchain, &storage, hash, false).await.context("Error while building block response")?;
    manager.message(format!("{}", serde_json::to_string_pretty(&response).context("Error while serializing")?));

    Ok(())
}


async fn pop_blocks(manager: &CommandManager<Arc<Blockchain>>, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let amount = arguments.get_value("amount")?.to_number()?;
    let blockchain = manager.get_data()?;
    if amount == 0 || amount >= blockchain.get_height() {
        return Err(anyhow::anyhow!("Invalid amount of blocks to pop").into());
    }

    info!("Trying to pop {} blocks from chain...", amount);
    let topoheight = blockchain.rewind_chain(amount as usize).await.context("Error while rewinding chain")?;
    info!("Chain as been rewinded until topoheight {}", topoheight);

    Ok(())
}