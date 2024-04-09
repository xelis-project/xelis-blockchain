pub mod rpc;
pub mod p2p;
pub mod core;
pub mod config;

use config::{DEV_PUBLIC_KEY, STABLE_LIMIT};
use fern::colors::Color;
use humantime::format_duration;
use log::{info, error, warn};
use p2p::P2pServer;
use rpc::{
    getwork_server::SharedGetWorkServer,
    rpc::get_block_response_for_hash
};
use xelis_common::{
    async_handler,
    config::{VERSION, XELIS_ASSET},
    context::Context,
    crypto::{
        Address,Hashable
    },
    difficulty::Difficulty,
    network::Network,
    prompt::{
        Prompt,
        command::{
            CommandManager,
            CommandError,
            Command,
            CommandHandler
        },
        PromptError,
        argument::{
            ArgumentManager,
            Arg,
            ArgType
        },
        LogLevel,
        self,
        ShareablePrompt
    },
    rpc_server::WebSocketServerHandler,
    serializer::Serializer,
    transaction::Transaction,
    utils::{
        format_hashrate,
        format_xelis,
        format_difficulty
    }
};
use crate::{
    core::{
        blockchain::{
            Config,
            Blockchain,
            get_block_reward
        },
        storage::{
            Storage,
            SledStorage
        }
    },
    config::{
        BLOCK_TIME_MILLIS,
        MILLIS_PER_SECOND
    }
};
use core::blockdag;
use std::{
    fs::File,
    io::Write,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration
};
use clap::Parser;
use anyhow::{
    Result,
    Context as AnyContext
};

#[derive(Parser)]
#[clap(version = VERSION, about = "XELIS: An innovate cryptocurrency with BlockDAG and Homomorphic Encryption enabling Smart Contracts")]
#[command(styles = xelis_common::get_cli_styles())]
pub struct NodeConfig {
    #[structopt(flatten)]
    nested: Config,
    /// Set log level
    #[clap(long, value_enum, default_value_t = LogLevel::Info)]
    log_level: LogLevel,
    /// Disable the log file
    #[clap(long)]
    disable_file_logging: bool,
    /// Log filename
    /// 
    /// By default filename is xelis-daemon.log.
    /// File will be stored in logs directory, this is only the filename, not the full path.
    /// Log file is rotated every day and has the format YYYY-MM-DD.xelis-daemon.log.
    #[clap(long, default_value_t = String::from("xelis-daemon.log"))]
    filename_log: String,
    /// Logs directory
    /// 
    /// By default it will be logs/ of the current directory.
    /// It must end with a / to be a valid folder.
    #[clap(long, default_value_t = String::from("logs/"))]
    logs_path: String,
    /// Network selected for chain
    #[clap(long, value_enum, default_value_t = Network::Mainnet)]
    network: Network
}

const BLOCK_TIME: Difficulty = Difficulty::from_u64(BLOCK_TIME_MILLIS / MILLIS_PER_SECOND);

#[tokio::main]
async fn main() -> Result<()> {
    let mut config: NodeConfig = NodeConfig::parse();

    let prompt = Prompt::new(config.log_level, &config.logs_path, &config.filename_log, config.disable_file_logging)?;
    info!("XELIS Blockchain running version: {}", VERSION);
    info!("----------------------------------------------");

    if config.nested.simulator.is_some() && config.network != Network::Dev {
        config.network = Network::Dev;
        warn!("Switching automatically to network {} because of simulator enabled", config.network);
    }

    let blockchain_config = config.nested;
    if let Some(path) = blockchain_config.dir_path.as_ref() {
        if !(path.ends_with("/") || path.ends_with("\\")) {
            return Err(anyhow::anyhow!("Path must end with / or \\"));
        }
    }

    let storage = {
        let use_cache = if blockchain_config.cache_size > 0 {
            Some(blockchain_config.cache_size)
        } else {
            None
        };

        let dir_path = blockchain_config.dir_path.clone().unwrap_or_default();
        SledStorage::new(dir_path, use_cache, config.network)?
    };

    let blockchain = Blockchain::new(blockchain_config, config.network, storage).await?;
    if let Err(e) = run_prompt(prompt, blockchain.clone(), config.network).await {
        error!("Error while running prompt: {}", e);
    }

    blockchain.stop().await;
    Ok(())
}

async fn run_prompt<S: Storage>(prompt: ShareablePrompt, blockchain: Arc<Blockchain<S>>, network: Network) -> Result<(), PromptError> {
    let mut context = Context::default();
    context.store(blockchain.clone());

    let command_manager = CommandManager::with_context(context, prompt.clone());
    command_manager.register_default_commands()?;

    // Register all our commands
    command_manager.add_command(Command::new("list_miners", "List all miners connected", CommandHandler::Async(async_handler!(list_miners::<S>))))?;
    command_manager.add_command(Command::new("list_peers", "List all peers connected", CommandHandler::Async(async_handler!(list_peers::<S>))))?;
    command_manager.add_command(Command::new("list_assets", "List all assets registered on chain", CommandHandler::Async(async_handler!(list_assets::<S>))))?;
    command_manager.add_command(Command::with_arguments("show_balance", "Show balance of an address", vec![], vec![Arg::new("history", ArgType::Number)], CommandHandler::Async(async_handler!(show_balance::<S>))))?;
    command_manager.add_command(Command::with_required_arguments("print_block", "Print block in json format", vec![Arg::new("hash", ArgType::Hash)], CommandHandler::Async(async_handler!(print_block::<S>))))?;
    command_manager.add_command(Command::new("top_block", "Print top block", CommandHandler::Async(async_handler!(top_block::<S>))))?;
    command_manager.add_command(Command::with_required_arguments("pop_blocks", "Delete last N blocks", vec![Arg::new("amount", ArgType::Number)], CommandHandler::Async(async_handler!(pop_blocks::<S>))))?;
    command_manager.add_command(Command::new("clear_mempool", "Clear all transactions in mempool", CommandHandler::Async(async_handler!(clear_mempool::<S>))))?;
    command_manager.add_command(Command::with_arguments("add_tx", "Add a TX in hex format in mempool", vec![Arg::new("hex", ArgType::String)], vec![Arg::new("broadcast", ArgType::Bool)], CommandHandler::Async(async_handler!(add_tx::<S>))))?;
    command_manager.add_command(Command::with_required_arguments("prune_chain", "Prune the chain until the specified topoheight", vec![Arg::new("topoheight", ArgType::Number)], CommandHandler::Async(async_handler!(prune_chain::<S>))))?;
    command_manager.add_command(Command::new("status", "Current daemon status", CommandHandler::Async(async_handler!(status::<S>))))?;
    command_manager.add_command(Command::with_optional_arguments("blacklist", "View blacklist or add a peer address in it", vec![Arg::new("address", ArgType::String)], CommandHandler::Async(async_handler!(blacklist::<S>))))?;
    command_manager.add_command(Command::with_optional_arguments("whitelist", "View whitelist or add a peer address in it", vec![Arg::new("address", ArgType::String)], CommandHandler::Async(async_handler!(whitelist::<S>))))?;
    command_manager.add_command(Command::with_optional_arguments("verify_chain", "Check chain supply", vec![Arg::new("topoheight", ArgType::Number)], CommandHandler::Async(async_handler!(verify_chain::<S>))))?;
    command_manager.add_command(Command::with_required_arguments("kick_peer", "Kick a peer using its ip:port", vec![Arg::new("address", ArgType::String)], CommandHandler::Async(async_handler!(kick_peer::<S>))))?;
    command_manager.add_command(Command::new("clear_caches", "Clear storage caches", CommandHandler::Async(async_handler!(clear_caches::<S>))))?;
    command_manager.add_command(Command::new("clear_rpc_connections", "Clear all WS connections from RPC", CommandHandler::Async(async_handler!(clear_rpc_connections::<S>))))?;
    command_manager.add_command(Command::with_optional_arguments("difficulty_dataset", "Create a dataset for difficulty from chain", vec![Arg::new("output", ArgType::String)], CommandHandler::Async(async_handler!(difficulty_dataset::<S>))))?;
    command_manager.add_command(Command::with_optional_arguments("mine_block", "Mine a block on testnet", vec![Arg::new("count", ArgType::Number)], CommandHandler::Async(async_handler!(mine_block::<S>))))?;


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

    let rpc = {
        let rpc = blockchain.get_rpc().read().await;
        rpc.clone()
    };

    let closure = |_: &_, _: _| async {
        let (peers, median) = match &p2p {
            Some(p2p) => (p2p.get_peer_count().await, p2p.get_median_topoheight_of_peers().await),
            None => (0, blockchain.get_topo_height())
        };

        let rpc_count = match &rpc {
            Some(rpc) => rpc.get_websocket().count_connections().await,
            None => 0
        };

        let miners = match &getwork {
            Some(getwork) => getwork.count_miners().await,
            None => 0
        };

        let mempool = {
            let mempool = blockchain.get_mempool().read().await;
            mempool.size()
        };

        let network_hashrate = (blockchain.get_difficulty().await / BLOCK_TIME).into();

        Ok(
            build_prompt_message(
                blockchain.get_topo_height(),
                median,
                network_hashrate,
                peers,
                rpc_count,
                miners,
                mempool,
                network
            )
        )
    };

    prompt.start(Duration::from_millis(100), Box::new(async_handler!(closure)), Some(&command_manager)).await
}

fn build_prompt_message(topoheight: u64, median_topoheight: u64, network_hashrate: f64, peers_count: usize, rpc_count: usize, miners_count: usize, mempool: usize, network: Network) -> String {
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
    let rpc_str = format!(
        "{}: {}",
        prompt::colorize_str(Color::Yellow, "RPC"),
        prompt::colorize_string(Color::Green, &format!("{}", rpc_count))
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
        "{} | {} | {} | {} | {} | {} | {} {}{} ",
        prompt::colorize_str(Color::Blue, "XELIS"),
        topoheight_str,
        network_hashrate_str,
        mempool_str,
        peers_str,
        rpc_str,
        miners_str,
        network_str,
        prompt::colorize_str(Color::BrightBlack, ">>")
    )
}

async fn verify_chain<S: Storage>(manager: &CommandManager, mut args: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;

    let storage = blockchain.get_storage().read().await;
    let mut pruned_topoheight = storage.get_pruned_topoheight().await.context("Error on pruned topoheight")?.unwrap_or(0);
    let mut expected_supply = if pruned_topoheight > 0 {
        let supply = storage.get_supply_at_topo_height(pruned_topoheight).await.context("Error while retrieving starting expected supply")?;
        pruned_topoheight += 1;
        supply
    } else {
        0
    };

    let topoheight = if args.has_argument("topoheight") {
        args.get_value("topoheight")?.to_number()?
    } else {
        blockchain.get_topo_height()
    };

    for topo in pruned_topoheight..=topoheight {
        let hash_at_topo = storage.get_hash_at_topo_height(topo).await.context("Error while retrieving hash at topo")?;
        let block_reward = if pruned_topoheight == 0 || topo - pruned_topoheight > STABLE_LIMIT {
            let block_reward = blockchain.get_block_reward(&*storage, &hash_at_topo, expected_supply, topo).await.context("Error while calculating block reward")?;
            let expected_block_reward = storage.get_block_reward_at_topo_height(topo).context("Error while retrieving block reward")?;
            // Verify the saved block reward
            if block_reward != expected_block_reward {
                manager.error(format!("Block reward saved is incorrect for {} at topoheight {}, got {} while expecting {}", hash_at_topo, topo, format_xelis(block_reward), format_xelis(expected_block_reward)));
                return Ok(())
            }
            block_reward
        } else {
            // We are too near from the pruned topoheight, as we don't know previous blocks we can't verify if block was side block or not for rewards
            // Let's trust its stored reward
            storage.get_block_reward_at_topo_height(topo).context("Error while retrieving block reward for pruned topo")?
        };

        let supply = storage.get_supply_at_topo_height(topo).await.context("Error while retrieving supply at topoheight")?;
        expected_supply += block_reward;

        // Verify the supply at block
        if supply != expected_supply {
            manager.error(format!("Error for block {} at topoheight {}, expected {} found {}", hash_at_topo, topo, expected_supply, supply));
            return Ok(())
        }
    }
    manager.message("Supply is valid");

    Ok(())
}

async fn kick_peer<S: Storage>(manager: &CommandManager, mut args: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    match blockchain.get_p2p().read().await.as_ref() {
        Some(p2p) => {
            let addr: SocketAddr = args.get_value("address")?.to_string_value()?.parse().context("Error while parsing socket address")?;
            let peer = {
                let peer_list = p2p.get_peer_list().read().await;
                peer_list.get_peer_by_addr(&addr).cloned()
            };

            if let Some(peer) = peer {
                peer.close().await.context("Error while closing peer connection")?;
                manager.message(format!("Peer {} has been kicked", addr));
            } else {
                manager.error(format!("Peer {} not found", addr));
            }
        },
        None => {
            manager.error("P2P is not enabled");
        }
    };

    Ok(())
}

async fn list_miners<S: Storage>(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    match blockchain.get_rpc().read().await.as_ref() {
        Some(rpc) => match rpc.getwork_server() {
            Some(getwork) => {
                let miners = getwork.get_miners().lock().await;
                manager.message(format!("Miners ({}):", miners.len()));
                for miner in miners.values() {
                    manager.message(format!("- {}", miner));
                }
            },
            None => {
                manager.message("No miners running!");
            }
        },
        None => {
            manager.message("No RPC server running!");
        }
    };

    Ok(())
}

async fn list_peers<S: Storage>(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
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

async fn list_assets<S: Storage>(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let assets = storage.get_assets().await.context("Error while retrieving assets")?;
    manager.message(format!("Registered assets ({}):", assets.len()));
    for asset in assets {
        manager.message(format!("- {}", asset));
    }
    Ok(())
}

async fn show_balance<S: Storage>(manager: &CommandManager, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let prompt = manager.get_prompt();
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
    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    if !storage.has_balance_for(&key, &asset).await.context("Error while checking if address has balance")? {
        manager.message("No balance found for address");
        return Ok(());
    }

    let (mut topo, mut version) = storage.get_last_balance(&key, &asset).await.context("Error while retrieving last balance")?;
    loop {
        history -= 1;
        manager.message(format!("Version at topoheight {}: {}", topo, version));

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

async fn print_block<S: Storage>(manager: &CommandManager, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let hash = arguments.get_value("hash")?.to_hash()?;
    let response = get_block_response_for_hash(blockchain, &storage, &hash, false).await.context("Error while building block response")?;
    manager.message(format!("{}", serde_json::to_string(&response).context("Error while serializing")?));

    Ok(())
}

async fn top_block<S: Storage>(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let hash = blockchain.get_top_block_hash_for_storage(&storage).await.context("Error on top block hash")?;
    let response = get_block_response_for_hash(blockchain, &storage, &hash, false).await.context("Error while building block response")?;
    manager.message(format!("{}", serde_json::to_string_pretty(&response).context("Error while serializing")?));

    Ok(())
}

async fn pop_blocks<S: Storage>(manager: &CommandManager, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let amount = arguments.get_value("amount")?.to_number()?;
    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    if amount == 0 || amount >= blockchain.get_height() {
        return Err(anyhow::anyhow!("Invalid amount of blocks to pop").into());
    }

    info!("Trying to pop {} blocks from chain...", amount);
    let topoheight = blockchain.rewind_chain(amount, false).await.context("Error while rewinding chain")?;
    info!("Chain as been rewinded until topoheight {}", topoheight);

    Ok(())
}

async fn clear_mempool<S: Storage>(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    info!("Clearing mempool...");
    let mut mempool = blockchain.get_mempool().write().await;
    mempool.clear();
    info!("Mempool cleared");

    Ok(())
}

// add manually a TX in mempool
async fn add_tx<S: Storage>(manager: &CommandManager, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let hex = arguments.get_value("hex")?.to_string_value()?;
    let broadcast = if arguments.has_argument("broadcast") {
        arguments.get_value("broadcast")?.to_bool()?
    } else {
        true
    };

    let tx = Transaction::from_hex(hex).context("Error while decoding tx in hexadecimal format")?;
    let hash = tx.hash();
    manager.message(format!("Adding TX {} to mempool...", hash));

    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    blockchain.add_tx_to_mempool_with_hash(tx, hash, broadcast).await.context("Error while adding TX to mempool")?;
    manager.message("TX has been added to mempool");
    Ok(())
}

async fn prune_chain<S: Storage>(manager: &CommandManager, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let topoheight = arguments.get_value("topoheight")?.to_number()?;
    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
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

async fn status<S: Storage>(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;

    let height = blockchain.get_height();
    let topoheight = blockchain.get_topo_height();
    let stableheight = blockchain.get_stable_height();
    let difficulty = blockchain.get_difficulty().await;

    let storage = blockchain.get_storage().read().await;
    let tips = storage.get_tips().await.context("Error while retrieving tips")?;
    let top_block_hash = blockchain.get_top_block_hash_for_storage(&storage).await.context("Error while retrieving top block hash")?;
    let avg_block_time = blockchain.get_average_block_time::<S>(&storage).await.context("Error while retrieving average block time")?;
    let supply = blockchain.get_supply().await.context("Error while retrieving supply")?;
    let accounts_count = storage.count_accounts().await.context("Error while counting accounts")?;
    let transactions_count = storage.count_transactions().await.context("Error while counting transactions")?;
    let blocks_count = storage.count_blocks().await.context("Error while counting blocks")?;
    let assets = storage.count_assets().await.context("Error while counting assets")?;
    let pruned_topoheight = storage.get_pruned_topoheight().await.context("Error while retrieving pruned topoheight")?;

    manager.message(format!("Height: {}", height));
    manager.message(format!("Stable Height: {}", stableheight));
    manager.message(format!("Topo Height: {}", topoheight));
    manager.message(format!("Difficulty: {}", format_difficulty(difficulty)));
    manager.message(format!("Network Hashrate: {}", format_hashrate((difficulty / BLOCK_TIME).into())));
    manager.message(format!("Top block hash: {}", top_block_hash));
    manager.message(format!("Average Block Time: {:.2}s", avg_block_time as f64 / MILLIS_PER_SECOND as f64));
    manager.message(format!("Target Block Time: {:.2}s", BLOCK_TIME_MILLIS as f64 / MILLIS_PER_SECOND as f64));
    manager.message(format!("Current Supply: {} XELIS", format_xelis(supply)));
    manager.message(format!("Current Block Reward: {} XELIS", format_xelis(get_block_reward(supply))));
    manager.message(format!("Stored accounts/transactions/blocks/assets: {}/{}/{}/{}", accounts_count, transactions_count, blocks_count, assets));

    manager.message(format!("Tips ({}):", tips.len()));
    for hash in tips {
        manager.message(format!("- {}", hash));
    }

    if let Some(pruned_topoheight) = pruned_topoheight {
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

async fn clear_rpc_connections<S: Storage>(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    match blockchain.get_rpc().read().await.as_ref() {
        Some(rpc) => match rpc.get_websocket().clear_connections().await {
            Ok(_) => {
                manager.message("All RPC connections cleared");
            },
            Err(e) => {
                manager.error(format!("Error while clearing RPC connections: {}", e));
            }
        },
        None => {
            manager.error("RPC is not enabled");
        }
    };

    Ok(())
}

async fn clear_caches<S: Storage>(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let mut storage = blockchain.get_storage().write().await;

    storage.clear_caches().await.context("Error while clearing caches")?;
    manager.message("Caches cleared");
    Ok(())
}

async fn blacklist<S: Storage>(manager: &CommandManager, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    match blockchain.get_p2p().read().await.as_ref() {
        Some(p2p) => {
            if arguments.has_argument("address") {
                let address: IpAddr = arguments.get_value("address")?.to_string_value()?.parse().context("Error while parsing socket address")?;
                let mut peer_list = p2p.get_peer_list().write().await;
                if peer_list.is_blacklisted(&address) {
                    peer_list.set_graylist_for_peer(&address);
                    manager.message(format!("Peer {} is not blacklisted anymore", address));
                } else {
                    peer_list.blacklist_address(&address).await;
                    manager.message(format!("Peer {} has been blacklisted", address));
                }
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

async fn whitelist<S: Storage>(manager: &CommandManager, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    match blockchain.get_p2p().read().await.as_ref() {
        Some(p2p) => {
            if arguments.has_argument("address") {
                let address: IpAddr = arguments.get_value("address")?.to_string_value()?.parse().context("Error while parsing socket address")?;
                let mut peer_list = p2p.get_peer_list().write().await;
                if peer_list.is_whitelisted(&address) {
                    peer_list.set_graylist_for_peer(&address);
                    manager.message(format!("Peer {} is not whitelisted anymore", address));
                } else {
                    peer_list.whitelist_address(&address);
                    manager.message(format!("Peer {} has been whitelisted", address));
                }
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

// Create a dataset from chain with solve time and difficulty at each block
async fn difficulty_dataset<S: Storage>(manager: &CommandManager, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let output_path = if arguments.has_argument("output") {
        arguments.get_value("output")?.to_string_value()?
    } else {
        "difficulty_dataset.csv".to_string()
    };

    manager.message(format!("Creating file {}...", output_path));
    let mut file = File::create(&output_path).context("Error while creating file")?;
    file.write(b"topoheight,solve_time_ms,difficulty\n").context("Error while writing header to file")?;
    
    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;

    manager.message("Creating difficulty dataset...");
    for topoheight in 0..=blockchain.get_topo_height() {
        // Retrieve block hash and header
        let (hash, header) = storage.get_block_header_at_topoheight(topoheight).await.context("Error while retrieving hash at topo")?;

        // Block difficulty
        let difficulty = storage.get_difficulty_for_block_hash(&hash).await.context("Error while retrieving difficulty")?;

        let solve_time = if topoheight == 0 {
            0            
        } else {
    
            // Retrieve best tip timestamp
            let (_, tip_timestamp) = blockdag::find_newest_tip_by_timestamp::<S, _>(&storage, header.get_tips().iter()).await.context("Error while finding best tip")?;
            let solve_time = header.get_timestamp() - tip_timestamp;
    
            solve_time
        };

        // Write to file
        file.write(format!("{},{},{}\n", topoheight, solve_time, difficulty).as_bytes()).context("Error while writing to file")?;
    }

    manager.message("Flushing file...");
    file.flush().context("Error while flushing file")?;
    manager.message(format!("Dataset written to {}", output_path));

    Ok(())
}

// Mine a block
async fn mine_block<S: Storage>(manager: &CommandManager, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let count = if arguments.has_argument("count") {
        arguments.get_value("count")?.to_number()?
    } else {
        1
    };

    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;

    // Prevent trying to mine a block on mainnet through this as it will keep busy the node for nothing
    if *blockchain.get_network() == Network::Mainnet {
        manager.error("This command is not allowed on mainnet");
        return Ok(())
    }

    let prompt = manager.get_prompt();
    manager.message(format!("Mining can take a while, are you sure you want to mine {} block(s)?", count));
    if !prompt.ask_confirmation().await.context("Error while asking confirmation")? {
        return Ok(())
    }

    manager.message(format!("Mining {} block(s)...", count));
    for _ in 0..count {
        let block = blockchain.mine_block(&DEV_PUBLIC_KEY).await.context("Error while mining block")?;
        let block_hash = block.hash();
        manager.message(format!("Block mined: {}", block_hash));

        let mut storage = blockchain.get_storage().write().await;
        blockchain.add_new_block_for_storage(&mut storage, block, true, true).await.context("Error while adding block to chain")?;
    }
    Ok(())
}
