pub mod rpc;
pub mod p2p;
pub mod core;
pub mod config;

use config::{DEV_PUBLIC_KEY, STABLE_LIMIT};
use human_bytes::human_bytes;
use humantime::format_duration;
use log::{debug, error, info, trace, warn};
use p2p::P2pServer;
use rpc::{
    getwork_server::SharedGetWorkServer,
    rpc::get_block_response_for_hash
};
use serde::{Deserialize, Serialize};
use xelis_common::{
    async_handler,
    config::{init, VERSION, XELIS_ASSET},
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
        ModuleConfig,
        ShareablePrompt,
        Color
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
        config::Config as InnerConfig,
        blockchain::{
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
use core::{
    blockdag,
    hard_fork::{
        get_pow_algorithm_for_version,
        get_version_at_height
    },
    storage::StorageMode
};
use std::{
    fs::File,
    io::Write,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::Arc,
    time::Duration
};
use clap::Parser;
use anyhow::{
    Result,
    Context as AnyContext
};

// Functions helpers for serde default values
fn default_filename_log() -> String {
    "xelis-daemon.log".to_owned()
}

fn default_logs_path() -> String {
    "logs/".to_owned()
}

#[derive(Debug, Clone, Parser, Serialize, Deserialize)]
pub struct LogConfig {
    /// Set log level
    #[clap(long, value_enum, default_value_t = LogLevel::Info)]
    #[serde(default)]
    log_level: LogLevel,
    /// Set file log level
    /// By default, it will be the same as log level
    #[clap(long, value_enum)]
    file_log_level: Option<LogLevel>,
    /// Disable the log file
    #[clap(long)]
    #[serde(default)]
    disable_file_logging: bool,
    /// Disable the log filename date based
    /// If disabled, the log file will be named xelis-daemon.log instead of YYYY-MM-DD.xelis-daemon.log
    #[clap(long)]
    #[serde(default)]
    disable_file_log_date_based: bool,
    /// Disable the usage of colors in log
    #[clap(long)]
    #[serde(default)]
    disable_log_color: bool,
    /// Disable terminal interactive mode
    /// You will not be able to write CLI commands in it or to have an updated prompt
    #[clap(long)]
    #[serde(default)]
    disable_interactive_mode: bool,
    /// Enable the log file auto compression
    /// If enabled, the log file will be compressed every day
    /// This will only work if the log file is enabled
    #[clap(long)]
    #[serde(default)]
    auto_compress_logs: bool,
    /// Log filename
    /// 
    /// By default filename is xelis-daemon.log.
    /// File will be stored in logs directory, this is only the filename, not the full path.
    /// Log file is rotated every day and has the format YYYY-MM-DD.xelis-daemon.log.
    #[clap(long, default_value_t = String::from("xelis-daemon.log"))]
    #[serde(default = "default_filename_log")]
    filename_log: String,
    /// Logs directory
    /// 
    /// By default it will be logs/ of the current directory.
    /// It must end with a / to be a valid folder.
    #[clap(long, default_value_t = String::from("logs/"))]
    #[serde(default = "default_logs_path")]
    logs_path: String,
    /// Module configuration for logs
    #[clap(long)]
    #[serde(default)]
    logs_modules: Vec<ModuleConfig>,
}

#[derive(Parser, Serialize, Deserialize)]
#[clap(version = VERSION, about = "XELIS is an innovative cryptocurrency built from scratch with BlockDAG, Homomorphic Encryption, Zero-Knowledge Proofs, and Smart Contracts.")]
#[command(styles = xelis_common::get_cli_styles())]
pub struct CliConfig {
    /// Blockchain core configuration
    #[structopt(flatten)]
    core: InnerConfig,
    /// Log configuration
    #[structopt(flatten)]
    log: LogConfig,
    /// Network selected for chain
    #[clap(long, value_enum, default_value_t = Network::Mainnet)]
    #[serde(default)]
    network: Network,
    /// DB cache size in bytes
    #[clap(long)]
    internal_cache_size: Option<u64>,
    /// Internal DB mode to use
    #[clap(long, value_enum, default_value_t = StorageMode::LowSpace)]
    #[serde(default)]
    internal_db_mode: StorageMode,
    /// JSON File to load the configuration from
    #[clap(long)]
    #[serde(skip)]
    #[serde(default)]
    config_file: Option<String>,
    /// Generate the template at the `config_file` path
    #[clap(long)]
    #[serde(skip)]
    #[serde(default)]
    generate_config_template: bool
}

const BLOCK_TIME: Difficulty = Difficulty::from_u64(BLOCK_TIME_MILLIS / MILLIS_PER_SECOND);

#[tokio::main]
async fn main() -> Result<()> {
    init();

    let mut config: CliConfig = CliConfig::parse();
    if let Some(path) = config.config_file.as_ref() {
        if config.generate_config_template {
            if Path::new(path).exists() {
                eprintln!("Config file already exists at {}", path);
                return Ok(());
            }

            let mut file = File::create(path).context("Error while creating config file")?;
            let json = serde_json::to_string_pretty(&config).context("Error while serializing config file")?;
            file.write_all(json.as_bytes()).context("Error while writing config file")?;
            println!("Config file template generated at {}", path);
            return Ok(());
        }

        let file = File::open(path).context("Error while opening config file")?;
        config = serde_json::from_reader(file).context("Error while reading config file")?;
    } else if config.generate_config_template {
        eprintln!("Provided config file path is required to generate the template with --config-file");
        return Ok(());
    }

    let blockchain_config = &config.core;
    if let Some(path) = blockchain_config.dir_path.as_ref() {
        if !(path.ends_with("/") || path.ends_with("\\")) {
            return Err(anyhow::anyhow!("Path must end with / or \\"));
        }

        // If logs path is default, we will change it to be in the same directory as the blockchain
        if config.log.logs_path == "logs/" {
            config.log.logs_path = format!("{}logs/", path);
        }
    }

    if blockchain_config.simulator.is_some() && config.network != Network::Dev {
        config.network = Network::Dev;
        warn!("Switching automatically to network {} because of simulator enabled", config.network);
    }

    let log_config = &config.log;
    let prompt = Prompt::new(
        log_config.log_level,
        &log_config.logs_path,
        &log_config.filename_log,
        log_config.disable_file_logging,
        log_config.disable_file_log_date_based,
        log_config.disable_log_color,
        log_config.auto_compress_logs,
        !log_config.disable_interactive_mode,
        log_config.logs_modules.clone(),
        log_config.file_log_level.unwrap_or(log_config.log_level)
    )?;

    info!("XELIS Blockchain running version: {}", VERSION);
    info!("----------------------------------------------");

    let storage = {
        let use_cache = if blockchain_config.cache_size > 0 {
            Some(blockchain_config.cache_size)
        } else {
            None
        };

        let dir_path = blockchain_config.dir_path.clone().unwrap_or_default();
        SledStorage::new(dir_path, use_cache, config.network, config.internal_cache_size, config.internal_db_mode)?
    };

    let blockchain = Blockchain::new(blockchain_config.clone(), config.network, storage).await?;
    if let Err(e) = run_prompt(prompt, blockchain.clone(), config).await {
        error!("Error while running prompt: {}", e);
    }

    blockchain.stop().await;
    Ok(())
}

async fn run_prompt<S: Storage>(prompt: ShareablePrompt, blockchain: Arc<Blockchain<S>>, config: CliConfig) -> Result<(), PromptError> {
    let network = config.network;

    let mut context = Context::default();
    context.store(blockchain.clone());
    context.store(config);

    let command_manager = CommandManager::with_context(context, prompt.clone());
    command_manager.register_default_commands()?;

    // Register all our commands
    command_manager.add_command(Command::with_optional_arguments("list_miners", "List all miners connected", vec![Arg::new("page", ArgType::Number)], CommandHandler::Async(async_handler!(list_miners::<S>))))?;
    command_manager.add_command(Command::with_optional_arguments("list_peers", "List all peers connected", vec![Arg::new("page", ArgType::Number)], CommandHandler::Async(async_handler!(list_peers::<S>))))?;
    command_manager.add_command(Command::with_optional_arguments("list_assets", "List all assets registered on chain", vec![Arg::new("page", ArgType::Number)], CommandHandler::Async(async_handler!(list_assets::<S>))))?;
    command_manager.add_command(Command::with_optional_arguments("show_peerlist", "Show the stored peerlist", vec![Arg::new("page", ArgType::Number)], CommandHandler::Async(async_handler!(show_stored_peerlist::<S>))))?;
    command_manager.add_command(Command::with_arguments("show_balance", "Show balance of an address", vec![], vec![Arg::new("history", ArgType::Number)], CommandHandler::Async(async_handler!(show_balance::<S>))))?;
    command_manager.add_command(Command::with_required_arguments("print_block", "Print block in json format", vec![Arg::new("hash", ArgType::Hash)], CommandHandler::Async(async_handler!(print_block::<S>))))?;
    command_manager.add_command(Command::with_required_arguments("dump_tx", "Dump TX in hexadecimal format", vec![Arg::new("hash", ArgType::Hash)], CommandHandler::Async(async_handler!(dump_tx::<S>))))?;
    command_manager.add_command(Command::with_required_arguments("dump_block", "Dump block in hexadecimal format", vec![Arg::new("hash", ArgType::Hash)], CommandHandler::Async(async_handler!(dump_block::<S>))))?;
    command_manager.add_command(Command::new("top_block", "Print top block", CommandHandler::Async(async_handler!(top_block::<S>))))?;
    command_manager.add_command(Command::with_required_arguments("pop_blocks", "Delete last N blocks", vec![Arg::new("amount", ArgType::Number)], CommandHandler::Async(async_handler!(pop_blocks::<S>))))?;
    command_manager.add_command(Command::new("clear_mempool", "Clear all transactions in mempool", CommandHandler::Async(async_handler!(clear_mempool::<S>))))?;
    command_manager.add_command(Command::with_arguments("add_tx", "Add a TX in hex format in mempool", vec![Arg::new("hex", ArgType::String)], vec![Arg::new("broadcast", ArgType::Bool)], CommandHandler::Async(async_handler!(add_tx::<S>))))?;
    command_manager.add_command(Command::with_required_arguments("prune_chain", "Prune the chain until the specified topoheight", vec![Arg::new("topoheight", ArgType::Number)], CommandHandler::Async(async_handler!(prune_chain::<S>))))?;
    command_manager.add_command(Command::new("status", "Current daemon status", CommandHandler::Async(async_handler!(status::<S>))))?;
    command_manager.add_command(Command::with_optional_arguments("blacklist", "View blacklist or add a peer ip in it", vec![Arg::new("ip", ArgType::String)], CommandHandler::Async(async_handler!(blacklist::<S>))))?;
    command_manager.add_command(Command::with_optional_arguments("whitelist", "View whitelist or add a peer ip in it", vec![Arg::new("ip", ArgType::String)], CommandHandler::Async(async_handler!(whitelist::<S>))))?;
    command_manager.add_command(Command::with_optional_arguments("verify_chain", "Check chain supply", vec![Arg::new("topoheight", ArgType::Number)], CommandHandler::Async(async_handler!(verify_chain::<S>))))?;
    command_manager.add_command(Command::with_required_arguments("kick_peer", "Kick a peer using its ip:port", vec![Arg::new("address", ArgType::String)], CommandHandler::Async(async_handler!(kick_peer::<S>))))?;
    command_manager.add_command(Command::with_required_arguments("temp_ban_address", "Temporarily ban an address in ip:port format", vec![Arg::new("address", ArgType::String), Arg::new("seconds", ArgType::Number)], CommandHandler::Async(async_handler!(temp_ban_address::<S>))))?;
    command_manager.add_command(Command::new("clear_caches", "Clear storage caches", CommandHandler::Async(async_handler!(clear_caches::<S>))))?;
    command_manager.add_command(Command::new("clear_rpc_connections", "Clear all WS connections from RPC", CommandHandler::Async(async_handler!(clear_rpc_connections::<S>))))?;
    command_manager.add_command(Command::new("clear_p2p_connections", "Clear all P2P connections", CommandHandler::Async(async_handler!(clear_p2p_connections::<S>))))?;
    command_manager.add_command(Command::new("clear_p2p_peerlist", "Clear P2P peerlist", CommandHandler::Async(async_handler!(clear_p2p_peerlist::<S>))))?;
    command_manager.add_command(Command::with_optional_arguments("difficulty_dataset", "Create a dataset for difficulty from chain", vec![Arg::new("output", ArgType::String)], CommandHandler::Async(async_handler!(difficulty_dataset::<S>))))?;
    command_manager.add_command(Command::with_optional_arguments("mine_block", "Mine a block on testnet", vec![Arg::new("count", ArgType::Number)], CommandHandler::Async(async_handler!(mine_block::<S>))))?;
    command_manager.add_command(Command::new("p2p_outgoing_connections", "Accept/refuse to connect to outgoing nodes", CommandHandler::Async(async_handler!(p2p_outgoing_connections::<S>))))?;
    command_manager.add_command(Command::with_required_arguments("add_peer", "Connect to a new peer using ip:port format", vec![Arg::new("address", ArgType::String)], CommandHandler::Async(async_handler!(add_peer::<S>))))?;
    command_manager.add_command(Command::new("list_unexecuted_transactions", "List all unexecuted transactions", CommandHandler::Async(async_handler!(list_unexecuted_transactions::<S>))))?;
    command_manager.add_command(Command::new("swap_blocks_executions_positions", "Swap the position of two blocks executions", CommandHandler::Async(async_handler!(swap_blocks_executions_positions::<S>))))?;
    command_manager.add_command(Command::new("print_balance", "Print the encrypted balance at a specific topoheight", CommandHandler::Async(async_handler!(print_balance::<S>))))?;
    command_manager.add_command(Command::new("estimate_db_size", "Estimate the database total size", CommandHandler::Async(async_handler!(estimate_db_size::<S>))))?;
    command_manager.add_command(Command::new("count_orphaned_blocks", "Count how many orphaned blocks we currently hold", CommandHandler::Async(async_handler!(count_orphaned_blocks::<S>))))?;
    command_manager.add_command(Command::new("show_json_config", "Show the current config in JSON", CommandHandler::Async(async_handler!(show_json_config::<S>))))?;
    command_manager.add_command(Command::new("broadcast_txs", "Broadcast all TXs in mempool if not done", CommandHandler::Async(async_handler!(broadcast_txs::<S>))))?;

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
        trace!("Retrieving P2P peers and median topoheight");
        let topoheight = blockchain.get_topo_height();
        let (peers, median, syncing_rate) = match &p2p {
            Some(p2p) => {
                let peer_list = p2p.get_peer_list();
                (
                    peer_list.size().await,
                    peer_list.get_median_topoheight(Some(topoheight)).await,
                    p2p.get_syncing_rate_bps(),
                )
            },
            None => (0, blockchain.get_topo_height(), None)
        };

        trace!("Retrieving RPC connections count");
        let rpc_count = match &rpc {
            Some(rpc) => rpc.get_websocket().count_connections().await,
            None => 0
        };

        trace!("Retrieving miners count");
        let miners = match &getwork {
            Some(getwork) => getwork.count_miners().await,
            None => 0
        };

        trace!("Retrieving mempool size");
        let mempool = {
            let mempool = blockchain.get_mempool().read().await;
            mempool.size()
        };

        trace!("Retrieving network hashrate");
        let network_hashrate: f64 = (blockchain.get_difficulty().await / BLOCK_TIME).into();

        trace!("Building prompt message");
        Ok( 
            build_prompt_message(
                &prompt,
                topoheight,
                median,
                network_hashrate,
                peers,
                rpc_count,
                miners,
                mempool,
                network,
                syncing_rate
            )
        )
    };

    prompt.start(Duration::from_secs(1), Box::new(async_handler!(closure)), Some(&command_manager)).await
}

fn build_prompt_message(
    prompt: &ShareablePrompt,
    topoheight: u64,
    median_topoheight: u64,
    network_hashrate: f64,
    peers_count: usize,
    rpc_count: usize,
    miners_count: usize,
    mempool: usize,
    network: Network,
    syncing_rate: Option<u64>
) -> String {
    let topoheight_str = format!(
        "{}: {}/{}",
        prompt.colorize_str(Color::Yellow, "TopoHeight"),
        prompt.colorize_string(Color::Green, &format!("{}", topoheight)),
        prompt.colorize_string(Color::Green, &format!("{}", median_topoheight))
    );
    let network_hashrate_str = format!(
        "{}: {}",
        prompt.colorize_str(Color::Yellow, "Network"),
        prompt.colorize_string(Color::Green, &format!("{}", format_hashrate(network_hashrate))),
    );
    let mempool_str = format!(
        "{}: {}",
        prompt.colorize_str(Color::Yellow, "Mempool"),
        prompt.colorize_string(Color::Green, &format!("{}", mempool))
    );
    let peers_str = format!(
        "{}: {} ",
        prompt.colorize_str(Color::Yellow, "Peers"),
        prompt.colorize_string(Color::Green, &format!("{}", peers_count))
    );
    let rpc_str = if rpc_count > 0 {
        format!(
            "| {}: {}",
            prompt.colorize_str(Color::Yellow, "RPC"),
            prompt.colorize_string(Color::Green, &format!("{}", rpc_count))
        )
    } else { "".to_owned() };

    let miners_str = if miners_count > 0 {
        format!(
            "| {}: {} ",
            prompt.colorize_str(Color::Yellow, "Miners"),
            prompt.colorize_string(Color::Green, &format!("{}", miners_count))
        )
    } else { "".to_owned() };

    let network_str = if !network.is_mainnet() {
        format!(
            "| {} ",
            prompt.colorize_string(Color::Red, &network.to_string())
        )
    } else { "".to_owned() };

    let syncing_str = if let Some(rate) = syncing_rate {
        format!(
            "| {}: {} ",
            prompt.colorize_str(Color::Yellow, "Sync"),
            prompt.colorize_string(Color::Green, &format!("{} bps", rate))
        )
    } else { "".to_owned() };

    format!(
        "{} | {} | {} | {} | {}{}{}{}{}{} ",
        prompt.colorize_str(Color::Blue, "XELIS"),
        topoheight_str,
        network_hashrate_str,
        mempool_str,
        peers_str,
        rpc_str,
        miners_str,
        syncing_str,
        network_str,
        prompt.colorize_str(Color::BrightBlack, ">>"),
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

    info!("Verifying chain supply from {} until topoheight {}", pruned_topoheight, topoheight);
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

        // Verify that we have a balance for each account updated
        let header = storage.get_block_header_by_hash(&hash_at_topo).await.context("Error while retrieving block header")?;
        if !storage.has_balance_at_exact_topoheight(header.get_miner(), &XELIS_ASSET, topo).await.context("Error while checking the miner balance version")? {
            manager.error(format!("No balance version found for miner {} at topoheight {} for block {}", header.get_miner().as_address(blockchain.get_network().is_mainnet()), topo, hash_at_topo));
            return Ok(())
        }

        for tx_hash in header.get_transactions() {
            if storage.is_tx_executed_in_block(tx_hash, &hash_at_topo).context("Error while checking if tx is executed in block")? {
                let transaction = storage.get_transaction(tx_hash).await.context("Error while retrieving transaction")?;

                if !storage.has_nonce_at_exact_topoheight(transaction.get_source(), topo).await.context("Error while checking the tx source nonce version")? {
                    manager.error(format!("No nonce version found for source {} at topoheight {}", transaction.get_source().as_address(blockchain.get_network().is_mainnet()), topo));
                    return Ok(())
                }

                for asset in transaction.get_assets() {
                    if !storage.has_balance_at_exact_topoheight(transaction.get_source(), asset, topo).await.context("Error while checking the tx source balance version")? {
                        manager.error(format!("No balance version found for source {} at topoheight {}", transaction.get_source().as_address(blockchain.get_network().is_mainnet()), topo));
                        return Ok(())
                    }
                }
            }
        }
    }
    manager.message("Supply is valid");

    Ok(())
}

// This is a debug command to see all unexecuted transactions in the chain that can happen due to DAG reorgs
async fn list_unexecuted_transactions<S: Storage>(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let unexecuted = storage.get_unexecuted_transactions().await.context("Error while retrieving unexecuted transactions")?;
    manager.message(format!("Unexecuted transactions ({}):", unexecuted.len()));
    for tx in unexecuted {
        manager.message(format!("- {}", tx));
    }
    Ok(())
}

async fn swap_blocks_executions_positions<S: Storage>(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let prompt = manager.get_prompt();
    let mut storage = blockchain.get_storage().write().await;

    let left = prompt.read_hash("Hash 1: ").await
        .context("Error while reading hash 1")?;
    let right = prompt.read_hash("Hash 2: ").await
        .context("Error while reading hash 2")?;

    storage.swap_blocks_executions_positions(&left, &right).await
        .context("Swap blocks executions positions")?;

    Ok(())
}

async fn print_balance<S: Storage>(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let prompt = manager.get_prompt();
    let storage = blockchain.get_storage().read().await;

    let address = prompt.read_input("Address: ", false).await
        .context("Error while reading address")?;
    let address = Address::from_string(&address)
        .context("Invalid address")?;

    let topoheight: u64 = prompt.read("Topoheight: ").await
        .context("Error while reading topoheight")?;

    let asset = prompt.read_hash("Asset (default XELIS): ").await.ok();
    let asset = asset.unwrap_or(XELIS_ASSET);

    let balance = storage.get_balance_at_exact_topoheight(&address.to_public_key(), &asset, topoheight).await
        .context("Error while retrieving balance")?;

    manager.message(format!("{}", balance));

    Ok(())
}

async fn estimate_db_size<S: Storage>(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let size = storage.estimate_size().await.context("Error while estimating size")?;
    manager.message(format!("Estimated size: {}", human_bytes(size as f64)));

    Ok(())
}

async fn count_orphaned_blocks<S: Storage>(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let count = storage.count_orphaned_blocks().await.context("Error while counting orphaned blocks")?;
    manager.message(format!("Orphaned blocks: {}", count));

    Ok(())
}

async fn show_json_config<S: Storage>(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let config: &CliConfig = context.get()?;
    let json = serde_json::to_string_pretty(config)
        .context("Error while serializing config")?;

    for line in json.lines() {
        manager.message(line);
    }

    Ok(())
}

async fn broadcast_txs<S: Storage>(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let p2p = blockchain.get_p2p().read().await;
    let p2p = match p2p.as_ref() {
        Some(p2p) => p2p,
        None => {
            manager.error("P2P is not enabled");
            return Ok(());
        }
    };

    let mempool = blockchain.get_mempool().read().await;
    let txs = mempool.get_txs();

    for hash in txs.keys() {
        info!("Broadcasting TX {}", hash);
        p2p.broadcast_tx_hash(hash.as_ref().clone()).await;
    }

    Ok(())
}

async fn kick_peer<S: Storage>(manager: &CommandManager, mut args: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    match blockchain.get_p2p().read().await.as_ref() {
        Some(p2p) => {
            let addr: SocketAddr = args.get_value("address")?.to_string_value()?.parse().context("Error while parsing socket address")?;
            let peer = {
                let peer_list = p2p.get_peer_list();
                peer_list.get_peer_by_addr(&addr).await
            };

            if let Some(peer) = peer {
                peer.signal_exit().await.context("Error while closing peer connection")?;
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

async fn temp_ban_address<S: Storage>(manager: &CommandManager, mut args: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    match blockchain.get_p2p().read().await.as_ref() {
        Some(p2p) => {
            let addr: IpAddr = args.get_value("address")?.to_string_value()?.parse().context("Error while parsing socket address")?;
            let seconds = args.get_value("seconds")?.to_number()? as u64;
            let peer_list = p2p.get_peer_list();

            peer_list.temp_ban_address(&addr, seconds, true).await.context("Error while banning address")?;
            manager.message(format!("Address {} has been banned for {} seconds", addr, seconds));
        },
        None => {
            manager.error("P2P is not enabled");
        }
    };

    Ok(())
}

const ELEMENTS_PER_PAGE: usize = 10;

async fn list_miners<S: Storage>(manager: &CommandManager, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let page = if arguments.has_argument("page") {
        arguments.get_value("page")?.to_number()? as usize
    } else {
        1
    };

    if page == 0 {
        return Err(CommandError::InvalidArgument("Page must be greater than 0".to_string()));
    }

    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    match blockchain.get_rpc().read().await.as_ref() {
        Some(rpc) => match rpc.getwork_server() {
            Some(getwork) => {
                let miners = getwork.get_miners().lock().await;
                if miners.is_empty() {
                    manager.message("No miners connected");
                    return Ok(());
                }

                let mut max_pages = miners.len() / ELEMENTS_PER_PAGE;
                if miners.len() % ELEMENTS_PER_PAGE != 0 {
                    max_pages += 1;
                }

                if page > max_pages {
                    return Err(CommandError::InvalidArgument(format!("Page must be less than maximum pages ({})", max_pages - 1)));
                }

                manager.message(format!("Miners (total {}) page {}/{}:", miners.len(), page, max_pages));
                for miner in miners.values().skip((page - 1) * ELEMENTS_PER_PAGE).take(ELEMENTS_PER_PAGE) {
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

async fn list_peers<S: Storage>(manager: &CommandManager, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let page = if arguments.has_argument("page") {
        arguments.get_value("page")?.to_number()? as usize
    } else {
        1
    };

    if page == 0 {
        return Err(CommandError::InvalidArgument("Page must be greater than 0".to_string()));
    }

    let context: std::sync::MutexGuard<Context> = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    match blockchain.get_p2p().read().await.as_ref() {
        Some(p2p) => {
            let peer_list = p2p.get_peer_list();
            let peers = peer_list.get_peers().read().await;
            if peers.is_empty() {
                manager.message("No peers connected");
                return Ok(());
            }

            let mut max_pages = peers.len() / ELEMENTS_PER_PAGE;
            if peers.len() % ELEMENTS_PER_PAGE != 0 {
                max_pages += 1;
            }

            if page > max_pages {
                return Err(CommandError::InvalidArgument(format!("Page must be less than maximum pages ({})", max_pages - 1)));
            }

            manager.message(format!("Peers (total {}) page {}/{}:", peers.len(), page, max_pages));
            for peer in peers.values().skip((page - 1) * ELEMENTS_PER_PAGE).take(ELEMENTS_PER_PAGE) {
                manager.message(format!("{}", peer));
            }
        },
        None => {
            manager.message("No P2p server running!");
        }
    };
    Ok(())
}

async fn list_assets<S: Storage>(manager: &CommandManager, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let page = if arguments.has_argument("page") {
        arguments.get_value("page")?.to_number()? as usize
    } else {
        1
    };

    if page == 0 {
        return Err(CommandError::InvalidArgument("Page must be greater than 0".to_string()));
    }

    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let assets = storage.get_assets().await.context("Error while retrieving assets")?;
    if assets.is_empty() {
        manager.message("No assets registered");
        return Ok(());
    }

    let mut max_pages = assets.len() / ELEMENTS_PER_PAGE;
    if assets.len() % ELEMENTS_PER_PAGE != 0 {
        max_pages += 1;
    }

    if page > max_pages {
        return Err(CommandError::InvalidArgument(format!("Page must be less than maximum pages ({})", max_pages - 1)));
    }

    manager.message(format!("Registered assets (total {}) page {}/{}:", assets.len(), page, max_pages));
    for asset in assets.iter().skip((page - 1) * ELEMENTS_PER_PAGE).take(ELEMENTS_PER_PAGE) {
        manager.message(format!("- {}", asset));
    }
    Ok(())
}

async fn show_stored_peerlist<S: Storage>(manager: &CommandManager, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let page = if arguments.has_argument("page") {
        arguments.get_value("page")?.to_number()? as usize
    } else {
        1
    };

    if page == 0 {
        return Err(CommandError::InvalidArgument("Page must be greater than 0".to_string()));
    }

    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    match blockchain.get_p2p().read().await.as_ref() {
        Some(p2p) => {
            let peer_list = p2p.get_peer_list();
            let peerlist: Vec<_> = peer_list.get_peerlist_entries().collect::<Result<Vec<_>, _>>().context("Error while retrieving stored peerlist")?;
            if peerlist.is_empty() {
                manager.message("No peers stored");
                return Ok(());
            }

            let mut max_pages = peerlist.len() / ELEMENTS_PER_PAGE;
            if peerlist.len() % ELEMENTS_PER_PAGE != 0 {
                max_pages += 1;
            }

            if page > max_pages {
                return Err(CommandError::InvalidArgument(format!("Page must be less than maximum pages ({})", max_pages - 1)));
            }

            manager.message(format!("Stored peerlist (total {}) page {}/{}:", peerlist.len(), page, max_pages));
            for (ip, state) in peerlist.iter().skip((page - 1) * ELEMENTS_PER_PAGE).take(ELEMENTS_PER_PAGE) {
                manager.message(format!("- {:15} | {}", ip, state));
            }
        },
        None => {
            manager.message("No P2p server running!");
        }
    };

    Ok(())
}

async fn show_balance<S: Storage>(manager: &CommandManager, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let prompt = manager.get_prompt();
    // read address
    let str_address = prompt.read_input(
        prompt.colorize_str(Color::Green, "Address: "),
        false
    ).await.context("Error while reading address")?;
    let address = Address::from_string(&str_address).context("Invalid address")?;

    // Read asset
    let asset = prompt.read_hash(
        prompt.colorize_str(Color::Green, "Asset (default XELIS): ")
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
    let json = serde_json::to_string_pretty(&response).context("Error while serializing")?;

    for line in json.lines() {
        manager.message(line);
    }

    Ok(())
}

async fn dump_tx<S: Storage>(manager: &CommandManager, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let hash = arguments.get_value("hash")?.to_hash()?;
    let tx = storage.get_transaction(&hash).await.context("Error while retrieving transaction")?;
    let hex = tx.to_hex();
    manager.message(format!("TX: {}", hex));

    Ok(())
}

async fn dump_block<S: Storage>(manager: &CommandManager, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let hash = arguments.get_value("hash")?.to_hash()?;
    let block = storage.get_block_by_hash(&hash).await.context("Error while retrieving block")?;
    let hex = block.to_hex();
    manager.message(format!("Block: {}", hex));

    Ok(())
}

async fn top_block<S: Storage>(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let hash = blockchain.get_top_block_hash_for_storage(&storage).await.context("Error on top block hash")?;
    let response = get_block_response_for_hash(blockchain, &storage, &hash, false).await.context("Error while building block response")?;
    let json = serde_json::to_string_pretty(&response).context("Error while serializing")?;

    for line in json.lines() {
        manager.message(line);
    }

    Ok(())
}

async fn pop_blocks<S: Storage>(manager: &CommandManager, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let amount = arguments.get_value("amount")?.to_number()?;
    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    if amount == 0 || amount >= blockchain.get_topo_height() {
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

    let tx = Transaction::from_hex(&hex).context("Error while decoding tx in hexadecimal format")?;
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

    debug!("Retrieving blockchain status");

    let height = blockchain.get_height();
    let topoheight = blockchain.get_topo_height();
    let stableheight = blockchain.get_stable_height();
    let stable_topoheight = blockchain.get_stable_topoheight();
    let difficulty = blockchain.get_difficulty().await;

    debug!("Retrieving blockchain info from storage");
    let storage = blockchain.get_storage().read().await;
    debug!("storage read lock acquired");

    let tips = storage.get_tips().await.context("Error while retrieving tips")?;
    let top_block_hash = blockchain.get_top_block_hash_for_storage(&storage).await.context("Error while retrieving top block hash")?;
    let avg_block_time = blockchain.get_average_block_time::<S>(&storage).await.context("Error while retrieving average block time")?;
    let supply = storage.get_supply_at_topo_height(topoheight).await.context("Error while retrieving supply")?;
    let burned_supply = storage.get_burned_supply_at_topo_height(topoheight).await.context("Error while retrieving burned supply")?;
    let accounts_count = storage.count_accounts().await.context("Error while counting accounts")?;
    let transactions_count = storage.count_transactions().await.context("Error while counting transactions")?;
    let blocks_count = storage.count_blocks().await.context("Error while counting blocks")?;
    let assets = storage.count_assets().await.context("Error while counting assets")?;
    let contracts = storage.count_contracts().await.context("Error while counting contracts")?;
    let pruned_topoheight = storage.get_pruned_topoheight().await.context("Error while retrieving pruned topoheight")?;
    let version = get_version_at_height(blockchain.get_network(), height);

    manager.message(format!("Height: {}", height));
    manager.message(format!("Stable Height: {}", stableheight));
    manager.message(format!("Stable Topo Height: {}", stable_topoheight));
    manager.message(format!("Topo Height: {}", topoheight));
    manager.message(format!("Difficulty: {}", format_difficulty(difficulty)));
    manager.message(format!("Network Hashrate: {}", format_hashrate((difficulty / BLOCK_TIME).into())));
    manager.message(format!("Top block hash: {}", top_block_hash));
    manager.message(format!("Average Block Time: {:.2}s", avg_block_time as f64 / MILLIS_PER_SECOND as f64));
    manager.message(format!("Target Block Time: {:.2}s", BLOCK_TIME_MILLIS as f64 / MILLIS_PER_SECOND as f64));
    manager.message(format!("Current Supply: {} XELIS", format_xelis(supply)));
    manager.message(format!("Burned Supply: {} XELIS", format_xelis(burned_supply)));
    manager.message(format!("Current Block Reward: {} XELIS", format_xelis(get_block_reward(supply))));
    manager.message(format!("Accounts/Transactions/Blocks/Assets/Contracts: {}/{}/{}/{}/{}", accounts_count, transactions_count, blocks_count, assets, contracts));
    manager.message(format!("Block Version: {}", version));
    manager.message(format!("POW Algorithm: {}", get_pow_algorithm_for_version(version)));

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

async fn clear_p2p_connections<S: Storage>(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    match blockchain.get_p2p().read().await.as_ref() {
        Some(p2p) => {
            p2p.clear_connections().await;
            manager.message("All P2P connections cleared");
        },
        None => {
            manager.error("P2P is not enabled");
        }
    };

    Ok(())
}

async fn clear_p2p_peerlist<S: Storage>(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    match blockchain.get_p2p().read().await.as_ref() {
        Some(p2p) => {
            let peerlist = p2p.get_peer_list();
            peerlist.clear_peerlist().await.context("Error while clearing peerlist")?;
            manager.message("P2P peerlist cleared");
        },
        None => {
            manager.error("P2P is not enabled");
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
            if arguments.has_argument("ip") {
                let address: IpAddr = arguments.get_value("ip")?.to_string_value()?.parse().context("Error while parsing socket address")?;
                let peer_list = p2p.get_peer_list();
                if peer_list.is_blacklisted(&address).await.context("Error while checking if peer is blacklisted")? {
                    peer_list.set_graylist_for_peer(&address).await.context("Error while setting graylist")?;
                    manager.message(format!("Peer {} is not blacklisted anymore", address));
                } else {
                    peer_list.blacklist_address(&address).await.context("Error while blacklisting peer")?;
                    manager.message(format!("Peer {} has been blacklisted", address));
                }
            } else {
                let peer_list = p2p.get_peer_list();
                let blacklist = peer_list.get_blacklist().context("Error while retrieving blacklist")?;
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
            if arguments.has_argument("ip") {
                let address: IpAddr = arguments.get_value("ip")?.to_string_value()?.parse().context("Error while parsing socket address")?;
                let peer_list = p2p.get_peer_list();
                if peer_list.is_whitelisted(&address).await.context("Error while checking if peer is whitelisted")? {
                    peer_list.set_graylist_for_peer(&address).await.context("Error while setting graylist")?;
                    manager.message(format!("Peer {} is not whitelisted anymore", address));
                } else {
                    peer_list.whitelist_address(&address).await.context("Error while whitelisting peer")?;
                    manager.message(format!("Peer {} has been whitelisted", address));
                }
            } else {
                let peer_list = p2p.get_peer_list();
                let whitelist = peer_list.get_whitelist().context("Error while retrieving whitelist")?;
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
        blockchain.add_new_block_for_storage(&mut *storage, block, true, true).await.context("Error while adding block to chain")?;
    }
    Ok(())
}

async fn p2p_outgoing_connections<S: Storage>(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    match blockchain.get_p2p().read().await.as_ref() {
        Some(p2p) => {
            let current = p2p.is_outgoing_connections_disabled();
            p2p.set_disable_outgoing_connections(!current);
            manager.message(format!("Outgoing connections are now {}", if current { "enabled" } else { "disabled" }));
        },
        None => {
            manager.error("P2P is not enabled");
        }
    };

    Ok(())
}

async fn add_peer<S: Storage>(manager: &CommandManager, mut args: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    match blockchain.get_p2p().read().await.as_ref() {
        Some(p2p) => {
            let addr: SocketAddr = args.get_value("address")?.to_string_value()?.parse().context("Error while parsing socket address")?;
            p2p.try_to_connect_to_peer(addr, false).await;
            manager.message(format!("Trying to connect to peer {}", addr));
        },
        None => {
            manager.error("P2P is not enabled");
        }
    };

    Ok(())
}