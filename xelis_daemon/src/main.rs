pub mod rpc;
pub mod p2p;
pub mod core;
pub mod config;

use fern::colors::Color;
use humantime::format_duration;
use log::{info, error, warn};
use p2p::P2pServer;
use rpc::{getwork_server::SharedGetWorkServer, rpc::get_block_response_for_hash};
use xelis_common::{
    prompt::{Prompt, command::{CommandManager, CommandError, Command, CommandHandler}, PromptError, argument::{ArgumentManager, Arg, ArgType}, LogLevel, self, ShareablePrompt},
    config::{VERSION, XELIS_ASSET}, utils::{format_hashrate, set_network_to, format_xelis, format_coin, format_difficulty}, async_handler, crypto::{address::Address, hash::Hashable}, network::Network, transaction::Transaction, serializer::Serializer
};
use crate::{
    core::{
        blockchain::{Config, Blockchain, get_block_reward},
        storage::{Storage, SledStorage}
    },
    config::{BLOCK_TIME_MILLIS, MILLIS_PER_SECOND}
};
use std::{sync::Arc, net::IpAddr};
use std::time::Duration;
use clap::Parser;
use anyhow::{Result, Context};

#[derive(Parser)]
#[clap(version = VERSION, about = "XELIS Daemon")]
pub struct NodeConfig {
    #[structopt(flatten)]
    nested: Config,
    /// Set log level
    #[clap(long, arg_enum, default_value_t = LogLevel::Info)]
    log_level: LogLevel,
    /// Disable the log file
    #[clap(short = 'f', long)]
    disable_file_logging: bool,
    /// Log filename
    #[clap(short = 'n', long, default_value_t = String::from("xelis.log"))]
    filename_log: String,
    /// Network selected for chain
    #[clap(long, arg_enum, default_value_t = Network::Mainnet)]
    network: Network
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut config: NodeConfig = NodeConfig::parse();

    let prompt = Prompt::new(config.log_level, config.filename_log, config.disable_file_logging)?;
    info!("XELIS Blockchain running version: {}", VERSION);
    info!("----------------------------------------------");

    if config.nested.simulator && config.network != Network::Dev {
        config.network = Network::Dev;
        warn!("Switching automatically to network {} because of simulator enabled", config.network);
    }
    set_network_to(config.network);

    let blockchain_config = config.nested;
    let storage = {
        let use_cache = if blockchain_config.cache_size > 0 {
            Some(blockchain_config.cache_size)
        } else {
            None
        };

        let dir_path = if let Some(path) = blockchain_config.dir_path.as_ref() {
            path.clone()
        } else {
            config.network.to_string().to_lowercase()
        };
        SledStorage::new(dir_path, use_cache, config.network)?
    };

    let blockchain = Blockchain::new(blockchain_config, config.network, storage).await?;
    if let Err(e) = run_prompt(prompt, blockchain.clone(), config.network).await {
        error!("Error while running prompt: {}", e);
    }

    blockchain.stop().await;
    Ok(())
}

async fn run_prompt<S: Storage>(prompt: ShareablePrompt<Arc<Blockchain<S>>>, blockchain: Arc<Blockchain<S>>, network: Network) -> Result<(), PromptError> {
    let mut command_manager: CommandManager<Arc<Blockchain<S>>> = CommandManager::default();
    // Set the data to use
    command_manager.set_data(Some(blockchain.clone()));

    // Register all our commands
    command_manager.add_command(Command::new("list_peers", "List all peers connected", CommandHandler::Async(async_handler!(list_peers))));
    command_manager.add_command(Command::new("list_assets", "List all assets registered on chain", CommandHandler::Async(async_handler!(list_assets))));
    command_manager.add_command(Command::with_arguments("show_balance", "Show balance of an address", vec![], vec![Arg::new("history", ArgType::Number)], CommandHandler::Async(async_handler!(show_balance))));
    command_manager.add_command(Command::with_required_arguments("print_block", "Print block in json format", vec![Arg::new("hash", ArgType::Hash)], CommandHandler::Async(async_handler!(print_block))));
    command_manager.add_command(Command::new("top_block", "Print top block", CommandHandler::Async(async_handler!(top_block))));
    command_manager.add_command(Command::with_required_arguments("pop_blocks", "Delete last N blocks", vec![Arg::new("amount", ArgType::Number)], CommandHandler::Async(async_handler!(pop_blocks))));
    command_manager.add_command(Command::new("clear_mempool", "Clear all transactions in mempool", CommandHandler::Async(async_handler!(clear_mempool))));
    command_manager.add_command(Command::with_arguments("add_tx", "Add a TX in hex format in mempool", vec![Arg::new("hex", ArgType::String)], vec![Arg::new("broadcast", ArgType::Bool)], CommandHandler::Async(async_handler!(add_tx))));
    command_manager.add_command(Command::with_required_arguments("prune_chain", "Prune the chain until the specified topoheight", vec![Arg::new("topoheight", ArgType::Number)], CommandHandler::Async(async_handler!(prune_chain))));
    command_manager.add_command(Command::new("status", "Current daemon status", CommandHandler::Async(async_handler!(status))));
    command_manager.add_command(Command::with_optional_arguments("blacklist", "View blacklist or add a peer address in it", vec![Arg::new("address", ArgType::String)], CommandHandler::Async(async_handler!(blacklist))));
    command_manager.add_command(Command::with_optional_arguments("whitelist", "View whitelist or add a peer address in it", vec![Arg::new("address", ArgType::String)], CommandHandler::Async(async_handler!(whitelist))));

    // Register the prompt in CommandManager in case we need it
    command_manager.set_prompt(Some(prompt.clone()));

    // set the CommandManager to use
    prompt.set_command_manager(Some(command_manager))?;

    // Don't keep the lock for ever
    let (p2p, getwork) = {
        let p2p: Option<Arc<P2pServer<S>>> = match blockchain.get_p2p().read().await.as_ref() {
            Some(p2p) => Some(p2p.clone()),
            None => None
        };
        let getwork: Option<SharedGetWorkServer<S>> = match blockchain.get_rpc().read().await.as_ref() {
            Some(rpc) => rpc.getwork_server().clone(),
            None => None
        };
        (p2p, getwork)
    };

    let closure = |_| async {
        let (peers, median) = match &p2p {
            Some(p2p) => (p2p.get_peer_count().await, p2p.get_median_topoheight_of_peers().await),
            None => (0, blockchain.get_topo_height())
        };

        let miners = match &getwork {
            Some(getwork) => getwork.count_miners().await,
            None => 0
        };

        let mempool = {
            let mempool = blockchain.get_mempool().read().await;
            mempool.size()
        };

        let network_hashrate = (blockchain.get_difficulty() / (BLOCK_TIME_MILLIS / MILLIS_PER_SECOND)) as f64;

        Ok(
            build_prompt_message(
                blockchain.get_topo_height(),
                median,
                network_hashrate,
                peers,
                miners,
                mempool,
                network
            )
        )
    };

    prompt.start(Duration::from_millis(100), &closure).await
}

fn build_prompt_message(topoheight: u64, median_topoheight: u64, network_hashrate: f64, peers_count: usize, miners_count: usize, mempool: usize, network: Network) -> String {
    let topoheight_str = format!(
        "{}: {}/{}",
        prompt::colorize_str(Color::Yellow, "TopoHeight"),
        prompt::colorize_string(Color::Green, &format!("{}", topoheight)),
        prompt::colorize_string(Color::Green, &format!("{}", median_topoheight))
    );
    let network_hashrate_str = format!(
        "{}: {}",
        prompt::colorize_str(Color::Yellow, "Network"),
        prompt::colorize_string(Color::Green, &format!("{}", format_hashrate(network_hashrate))),
    );
    let mempool_str = format!(
        "{}: {}",
        prompt::colorize_str(Color::Yellow, "Mempool"),
        prompt::colorize_string(Color::Green, &format!("{}", mempool))
    );
    let peers_str = format!(
        "{}: {}",
        prompt::colorize_str(Color::Yellow, "Peers"),
        prompt::colorize_string(Color::Green, &format!("{}", peers_count))
    );
    let miners_str = format!(
        "{}: {}",
        prompt::colorize_str(Color::Yellow, "Miners"),
        prompt::colorize_string(Color::Green, &format!("{}", miners_count))
    );


    let network_str = if !network.is_mainnet() {
        format!(
            "{} ",
            prompt::colorize_string(Color::Red, &network.to_string())
        )
    } else { "".into() };

    format!(
        "{} | {} | {} | {} | {} | {} {}{} ",
        prompt::colorize_str(Color::Blue, "XELIS"),
        topoheight_str,
        network_hashrate_str,
        mempool_str,
        peers_str,
        miners_str,
        network_str,
        prompt::colorize_str(Color::BrightBlack, ">>")
    )
}

async fn list_peers<S: Storage>(manager: &CommandManager<Arc<Blockchain<S>>>, _: ArgumentManager) -> Result<(), CommandError> {
    let blockchain = manager.get_data()?;
    match blockchain.get_p2p().read().await.as_ref() {
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

async fn list_assets<S: Storage>(manager: &CommandManager<Arc<Blockchain<S>>>, _: ArgumentManager) -> Result<(), CommandError> {
    let blockchain = manager.get_data()?;
    let storage = blockchain.get_storage().read().await;
    let assets = storage.get_assets().await.context("Error while retrieving assets")?;
    manager.message(format!("Registered assets ({}):", assets.len()));
    for asset in assets {
        manager.message(format!("- {}", asset));
    }
    Ok(())
}

async fn show_balance<S: Storage>(manager: &CommandManager<Arc<Blockchain<S>>>, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let prompt = manager.get_prompt()?;
    // read address
    let str_address = prompt.read_input(
        prompt::colorize_str(Color::Green, "Address: "),
        false
    ).await.context("Error while reading address")?;
    let address = Address::from_string(&str_address).context("Invalid address")?;

    // Read asset
    let asset = prompt.read_hash(
        prompt::colorize_str(Color::Green, "Asset (default XELIS): ")
    ).await.ok();

    let asset = asset.unwrap_or(XELIS_ASSET);

    let mut history = if arguments.has_argument("history") {
        let value = arguments.get_value("history")?.to_number()?;
        if value == 0 {
            return Err(CommandError::InvalidArgument("history must be a positive number".into()));
        }
        value
    } else {
        1
    };

    let key = address.to_public_key();
    let blockchain = manager.get_data()?;
    let storage = blockchain.get_storage().read().await;
    let asset_data = storage.get_asset_data(&asset).context("Error while retrieving asset data")?;
    let (mut topo, mut version) = storage.get_last_balance(&key, &asset).await.context("Error while retrieving last balance")?;
    loop {
        history -= 1;
        manager.message(format!("Balance found at topoheight {}: {}", topo, format_coin(version.get_balance(), asset_data.get_decimals())));

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

async fn print_block<S: Storage>(manager: &CommandManager<Arc<Blockchain<S>>>, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let blockchain = manager.get_data()?;
    let storage = blockchain.get_storage().read().await;
    let hash = arguments.get_value("hash")?.to_hash()?;
    let response = get_block_response_for_hash(blockchain, &storage, hash, false).await.context("Error while building block response")?;
    manager.message(format!("{}", serde_json::to_string_pretty(&response).context("Error while serializing")?));

    Ok(())
}

async fn top_block<S: Storage>(manager: &CommandManager<Arc<Blockchain<S>>>, _: ArgumentManager) -> Result<(), CommandError> {
    let blockchain = manager.get_data()?;
    let storage = blockchain.get_storage().read().await;
    let hash = blockchain.get_top_block_hash().await.context("Error on top block hash")?;
    let response = get_block_response_for_hash(blockchain, &storage, hash, false).await.context("Error while building block response")?;
    manager.message(format!("{}", serde_json::to_string_pretty(&response).context("Error while serializing")?));

    Ok(())
}

async fn pop_blocks<S: Storage>(manager: &CommandManager<Arc<Blockchain<S>>>, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let amount = arguments.get_value("amount")?.to_number()?;
    let blockchain = manager.get_data()?;
    if amount == 0 || amount >= blockchain.get_height() {
        return Err(anyhow::anyhow!("Invalid amount of blocks to pop").into());
    }

    info!("Trying to pop {} blocks from chain...", amount);
    let topoheight = blockchain.rewind_chain(amount).await.context("Error while rewinding chain")?;
    info!("Chain as been rewinded until topoheight {}", topoheight);

    Ok(())
}

async fn clear_mempool<S: Storage>(manager: &CommandManager<Arc<Blockchain<S>>>, _: ArgumentManager) -> Result<(), CommandError> {
    let blockchain = manager.get_data()?;
    info!("Clearing mempool...");
    let mut mempool = blockchain.get_mempool().write().await;
    mempool.clear();
    info!("Mempool cleared");

    Ok(())
}

// add manually a TX in mempool
async fn add_tx<S: Storage>(manager: &CommandManager<Arc<Blockchain<S>>>, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let hex = arguments.get_value("hex")?.to_string_value()?;
    let broadcast = if arguments.has_argument("broadcast") {
        arguments.get_value("broadcast")?.to_bool()?
    } else {
        true
    };

    let tx = Transaction::from_hex(hex).context("Error while decoding tx in hexadecimal format")?;
    let hash = tx.hash();
    manager.message(format!("Adding TX {} to mempool...", hash));

    let blockchain = manager.get_data()?;
    blockchain.add_tx_to_mempool_with_hash(tx, hash, broadcast).await.context("Error while adding TX to mempool")?;
    manager.message("TX has been added to mempool");
    Ok(())
}

async fn prune_chain<S: Storage>(manager: &CommandManager<Arc<Blockchain<S>>>, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let topoheight = arguments.get_value("topoheight")?.to_number()?;
    let blockchain = manager.get_data()?;
    manager.message(format!("Pruning chain until maximum topoheight {}", topoheight));
    let pruned_topoheight = match blockchain.prune_until_topoheight(topoheight).await {
        Ok(topoheight) => topoheight,
        Err(e) => {
            manager.error(format!("Error while pruning chain: {}", e));
            return Ok(());
        }
    };
    manager.message(format!("Chain has been pruned until topoheight {}", pruned_topoheight));
    Ok(())
}

async fn status<S: Storage>(manager: &CommandManager<Arc<Blockchain<S>>>, _: ArgumentManager) -> Result<(), CommandError> {
    let blockchain = manager.get_data()?;
    let storage = blockchain.get_storage().read().await;

    let height = blockchain.get_height();
    let topoheight = blockchain.get_topo_height();
    let stableheight = blockchain.get_stable_height();
    let difficulty = blockchain.get_difficulty();
    let tips = storage.get_tips().await.context("Error while retrieving tips")?;
    let top_block_hash = blockchain.get_top_block_hash().await.context("Error while retrieving top block hash")?;
    let avg_block_time = blockchain.get_average_block_time_for_storage(&storage).await.context("Error while retrieving average block time")?;
    let supply = blockchain.get_supply().await.context("Error while retrieving supply")?;

    manager.message(format!("Height: {}", height));
    manager.message(format!("Stable Height: {}", stableheight));
    manager.message(format!("Topo Height: {}", topoheight));
    manager.message(format!("Difficulty: {}", format_difficulty(difficulty)));
    manager.message(format!("Network Hashrate: {}", format_hashrate((difficulty / (BLOCK_TIME_MILLIS / MILLIS_PER_SECOND)) as f64)));
    manager.message(format!("Top block hash: {}", top_block_hash));
    manager.message(format!("Average Block Time: {:.2}s", avg_block_time as f64 / MILLIS_PER_SECOND as f64));
    manager.message(format!("Target Block Time: {:.2}s", BLOCK_TIME_MILLIS as f64 / MILLIS_PER_SECOND as f64));
    manager.message(format!("Current Supply: {} XELIS", format_xelis(supply)));
    manager.message(format!("Current Block Reward: {} XELIS", format_xelis(get_block_reward(supply))));

    manager.message(format!("Tips ({}):", tips.len()));
    for hash in tips {
        manager.message(format!("- {}", hash));
    }

    if let Some(pruned_topoheight) = storage.get_pruned_topoheight().context("Error while retrieving pruned topoheight")? {
        manager.message(format!("Chain is pruned until topoheight {}", pruned_topoheight));
    } else {
        manager.message("Chain is in full mode");
    }

    let elapsed_seconds = manager.running_since().as_secs();
    let elapsed = format_duration(Duration::from_secs(elapsed_seconds)).to_string();
    manager.message(format!("Uptime: {}", elapsed));
    manager.message(format!("Running on version {}", VERSION));
    Ok(())
}

async fn blacklist<S: Storage>(manager: &CommandManager<Arc<Blockchain<S>>>, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let blockchain: &Arc<Blockchain<S>> = manager.get_data()?;
    match blockchain.get_p2p().read().await.as_ref() {
        Some(p2p) => {
            if arguments.has_argument("address") {
                let address: IpAddr = arguments.get_value("address")?.to_string_value()?.parse().context("Error while parsing socket address")?;
                let peer_list = p2p.get_peer_list();
                peer_list.write().await.blacklist_address(&address).await;
                manager.message(format!("Peer {} has been blacklisted", address));
            } else {
                let peer_list = p2p.get_peer_list().read().await;
                let blacklist = peer_list.get_blacklist();
                manager.message(format!("Current blacklist ({}):", blacklist.len()));
                for (ip, peer) in blacklist {
                    manager.message(format!("- {}: {}", ip, peer));
                }
            }
        },
        None => {
            manager.error("P2P is not enabled");
        }
    };

    Ok(())
}

async fn whitelist<S: Storage>(manager: &CommandManager<Arc<Blockchain<S>>>, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let blockchain: &Arc<Blockchain<S>> = manager.get_data()?;
    match blockchain.get_p2p().read().await.as_ref() {
        Some(p2p) => {
            if arguments.has_argument("address") {
                let address: IpAddr = arguments.get_value("address")?.to_string_value()?.parse().context("Error while parsing socket address")?;
                let peer_list = p2p.get_peer_list();
                peer_list.write().await.whitelist_address(&address);
                manager.message(format!("Peer {} has been whitelisted", address));
            } else {
                let peer_list = p2p.get_peer_list().read().await;
                let whitelist = peer_list.get_whitelist();
                manager.message(format!("Current whitelist ({}):", whitelist.len()));
                for (ip, peer) in whitelist {
                    manager.message(format!("- {}: {}", ip, peer));
                }
            }
        },
        None => {
            manager.error("P2P is not enabled");
        }
    };

    Ok(())
}