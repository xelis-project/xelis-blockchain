use std::{sync::Arc, time::Duration, path::Path};

use anyhow::{Result, Context};
use xelis_wallet::config::DIR_PATH;
use fern::colors::Color;
use log::{error, info};
use clap::Parser;
use xelis_common::{config::{
    DEFAULT_DAEMON_ADDRESS,
    VERSION, XELIS_ASSET
}, prompt::{Prompt, command::{CommandManager, Command, CommandHandler, CommandError}, argument::{Arg, ArgType, ArgumentManager}, LogLevel}, async_handler, crypto::{address::{Address, AddressType}, hash::Hashable}, transaction::{TransactionType, Transaction}, globals::{format_coin, set_network_to}, serializer::Serializer, network::Network, api::wallet::FeeBuilder};
use xelis_wallet::wallet::Wallet;

#[cfg(feature = "api_server")]
use xelis_wallet::api::AuthConfig;

// This struct is used to configure the RPC Server
// In case we want to enable it instead of starting
// the XSWD Server
#[cfg(feature = "api_server")]
#[derive(Debug, clap::StructOpt)]
pub struct RPCConfig {
    /// RPC Server bind address
    #[clap(long)]
    rpc_bind_address: Option<String>,
    /// username for RPC authentication
    #[clap(long)]
    rpc_username: Option<String>,
    /// password for RPC authentication
    #[clap(long)]
    rpc_password: Option<String>
}

#[derive(Parser)]
#[clap(version = VERSION, about = "XELIS Wallet")]
pub struct Config {
    /// Daemon address to use
    #[clap(short = 'a', long, default_value_t = String::from(DEFAULT_DAEMON_ADDRESS))]
    daemon_address: String,
    /// Disable online mode
    #[clap(short, long)]
    offline_mode: bool,
    /// Set log level
    #[clap(long, arg_enum, default_value_t = LogLevel::Info)]
    log_level: LogLevel,
    /// Disable the log file
    #[clap(short = 'f', long)]
    disable_file_logging: bool,
    /// Log filename
    #[clap(short = 'l', long, default_value_t = String::from("xelis-wallet.log"))]
    filename_log: String,
    /// Set name path for wallet storage
    #[clap(short, long, default_value_t = String::from("default"))]
    name: String,
    /// Password used to open wallet
    #[clap(short, long)]
    password: String,
    /// Restore wallet using seed
    #[clap(short, long)]
    seed: Option<String>,
    /// Network selected for chain
    #[clap(long, arg_enum, default_value_t = Network::Mainnet)]
    network: Network,
    /// RPC Server configuration
    #[cfg(feature = "api_server")]
    #[structopt(flatten)]
    rpc: RPCConfig,
    /// XSWD Server configuration
    #[cfg(feature = "api_server")]
    #[clap(long)]
    enable_xswd: bool
}

#[tokio::main]
async fn main() -> Result<()> {
    let config: Config = Config::parse();
    #[cfg(feature = "api_server")]
    { // Sanity check
        // check that we don't have both server enabled
        if config.enable_xswd && config.rpc.rpc_bind_address.is_some() {
            error!("Invalid parameters configuration: RPC Server and XSWD cannot be enabled at the same time");
            return Ok(()); // exit
        }

        // check that username/password is not in param if bind address is not set
        if config.rpc.rpc_bind_address.is_none() && (config.rpc.rpc_password.is_some() || config.rpc.rpc_username.is_some()) {
            error!("Invalid parameters configuration for rpc password and username: RPC Server is not enabled");
            return Ok(())
        }

        // check that username/password is set together if bind address is set
        if config.rpc.rpc_bind_address.is_some() && config.rpc.rpc_password.is_some() != config.rpc.rpc_username.is_some() {
            error!("Invalid parameters configuration: usernamd AND password must be provided");
            return Ok(())
        }
    }

    set_network_to(config.network);

    let prompt = Prompt::new(config.log_level, config.filename_log, config.disable_file_logging)?;
    let dir = format!("{}{}", DIR_PATH, config.name);

    let wallet = if Path::new(&dir).is_dir() {
        info!("Opening wallet {}", dir);
        Wallet::open(dir, config.password, config.network)?
    } else {
        info!("Creating a new wallet at {}", dir);
        Wallet::create(dir, config.password, config.seed, config.network)?
    };

    if !config.offline_mode {
        info!("Trying to connect to daemon at '{}'", config.daemon_address);
        if let Err(e) = wallet.set_online_mode(&config.daemon_address).await {
            error!("Couldn't connect to daemon: {}", e);
            info!("You can activate online mode using 'online_mode [daemon_address]'");
        } else {
            info!("Online mode enabled");
        }
    }

    #[cfg(feature = "api_server")]
    {
        if config.enable_xswd && config.rpc.rpc_bind_address.is_some() {
            error!("Invalid parameters configuration: RPC Server and XSWD cannot be enabled at the same time");
            return Ok(()); // exit
        }

        if let Some(address) = config.rpc.rpc_bind_address {
            let auth_config = if let (Some(username), Some(password)) = (config.rpc.rpc_username, config.rpc.rpc_password) {
                Some(AuthConfig {
                    username,
                    password
                })
            } else {
                None
            };

            info!("Enabling RPC Server on {} {}", address, if auth_config.is_some() { "with authentication" } else { "without authentication" });
            if let Err(e) = wallet.enable_rpc_server(address, auth_config).await {
                error!("Error while enabling RPC Server: {}", e);
            }
        } else if config.enable_xswd {
            if let Err(e) = wallet.enable_xswd().await {
                error!("Error while enabling XSWD Server: {}", e);
            }
        }
    }

    if let Err(e) = run_prompt(prompt, wallet, config.network).await {
        error!("Error while running prompt: {}", e);
    }

    Ok(())
}

async fn run_prompt(prompt: Arc<Prompt>, wallet: Arc<Wallet>, network: Network) -> Result<()> {
    let mut command_manager: CommandManager<Arc<Wallet>> = CommandManager::default();
    command_manager.add_command(Command::new("change_password", "Set a new password to open your wallet", None, CommandHandler::Async(async_handler!(change_password))));
    command_manager.add_command(Command::with_required_arguments("transfer", "Send asset to a specified address", vec![Arg::new("address", ArgType::String), Arg::new("amount", ArgType::Number)], Some(Arg::new("asset", ArgType::Hash)), CommandHandler::Async(async_handler!(transfer))));
    command_manager.add_command(Command::with_required_arguments("burn", "Burn amount of asset", vec![Arg::new("asset", ArgType::Hash), Arg::new("amount", ArgType::Number)], None, CommandHandler::Async(async_handler!(burn))));
    command_manager.add_command(Command::new("display_address", "Show your wallet address", None, CommandHandler::Async(async_handler!(display_address))));
    command_manager.add_command(Command::new("balance", "Show your current balance", Some(Arg::new("asset", ArgType::String)), CommandHandler::Async(async_handler!(balance))));
    command_manager.add_command(Command::new("history", "Show all your transactions", Some(Arg::new("page", ArgType::Number)), CommandHandler::Async(async_handler!(history))));
    command_manager.add_command(Command::new("online_mode", "Set your wallet in online mode", Some(Arg::new("daemon_address", ArgType::String)), CommandHandler::Async(async_handler!(online_mode))));
    command_manager.add_command(Command::new("offline_mode", "Set your wallet in offline mode", None, CommandHandler::Async(async_handler!(offline_mode))));
    command_manager.add_command(Command::new("rescan", "Rescan balance and transactions", Some(Arg::new("topoheight", ArgType::Number)), CommandHandler::Async(async_handler!(rescan))));
    command_manager.add_command(Command::new("seed", "Show seed of selected language", Some(Arg::new("language", ArgType::Number)), CommandHandler::Async(async_handler!(seed))));
    command_manager.add_command(Command::new("nonce", "Show current nonce", None, CommandHandler::Async(async_handler!(nonce))));

    #[cfg(feature = "api_server")]
    {
        // Unauthenticated RPC Server can only be created by launch arguments option
        command_manager.add_command(Command::with_required_arguments("start_rpc_server", "Start the RPC Server", vec![
            Arg::new("bind_address", ArgType::String),
            Arg::new("username", ArgType::String),
            Arg::new("password", ArgType::String)
        ], None, CommandHandler::Async(async_handler!(start_rpc_server))));

        command_manager.add_command(Command::new("start_xswd", "Start the XSWD Server",  None, CommandHandler::Async(async_handler!(start_xswd))));

        // Stop API Server (RPC or XSWD)
        command_manager.add_command(Command::new("stop_api_server", "Stop the API Server", None, CommandHandler::Async(async_handler!(stop_api_server))));
    }

    command_manager.set_data(Some(wallet.clone()));
    command_manager.set_prompt(Some(prompt.clone()));

    let addr_str = {
        let addr = &wallet.get_address().to_string()[..8];
        Prompt::colorize_str(Color::Yellow, addr)
    };
    let closure = || async {
        let storage = wallet.get_storage().read().await;
        let topoheight_str = format!(
            "{}: {}",
            Prompt::colorize_str(Color::Yellow, "TopoHeight"),
            Prompt::colorize_string(Color::Green, &format!("{}", storage.get_daemon_topoheight().unwrap_or(0)))
        );
        let balance = format!(
            "{}: {}",
            Prompt::colorize_str(Color::Yellow, "Balance"),
            Prompt::colorize_string(Color::Green, &format_coin(storage.get_balance_for(&XELIS_ASSET).unwrap_or(0))),
        );
        let status = if wallet.is_online().await {
            Prompt::colorize_str(Color::Green, "Online")
        } else {
            Prompt::colorize_str(Color::Red, "Offline")
        };
        let network_str = if !network.is_mainnet() {
            format!(
                "{} ",
                Prompt::colorize_string(Color::Red, &network.to_string())
            )
        } else { "".into() };

        format!(
            "{} | {} | {} | {} | {} {}{} ",
            Prompt::colorize_str(Color::Blue, "XELIS Wallet"),
            addr_str,
            topoheight_str,
            balance,
            status,
            network_str,
            Prompt::colorize_str(Color::BrightBlack, ">>")
        )
    };
    prompt.start(Duration::from_millis(100), &closure, command_manager).await?;
    Ok(())
}

// Change wallet password
async fn change_password(manager: &CommandManager<Arc<Wallet>>, _: ArgumentManager) -> Result<(), CommandError> {
    let wallet = manager.get_data()?;
    let prompt = manager.get_prompt()?;

    let old_password = prompt.read_input(Prompt::colorize_str(Color::BrightRed, "Current Password: "), true)
        .await
        .context("Error while asking old password")?;

    let new_password = prompt.read_input(Prompt::colorize_str(Color::BrightRed, "New Password: "), true)
        .await
        .context("Error while asking new password")?;

    manager.message("Changing password...");
    wallet.set_password(old_password, new_password).await?;
    manager.message("Your password has been changed!");
    Ok(())
}

// Create a new transfer to a specified address
async fn transfer(manager: &CommandManager<Arc<Wallet>>, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let str_address = arguments.get_value("address")?.to_string_value()?;
    let amount = arguments.get_value("amount")?.to_number()?;
    let address = Address::from_string(&str_address).context("Invalid address")?;

    let asset = if arguments.has_argument("asset") {
        arguments.get_value("asset")?.to_hash()?
    } else {
        XELIS_ASSET // default asset selected is XELIS
    };

    manager.message(format!("Sending {} of {} to {}", format_coin(amount), asset, address.to_string()));

    let wallet = manager.get_data()?;
    manager.message("Building transaction...");

    let (key, address_type) = address.split();
    let extra_data = match address_type {
        AddressType::Normal => None,
        AddressType::Data(data) => Some(data)
    };

    let tx = {
        let storage = wallet.get_storage().read().await;
        let transfer = wallet.create_transfer(&storage, asset, key, extra_data, amount)?;
        wallet.create_transaction(&storage, TransactionType::Transfer(vec![transfer]), FeeBuilder::Multiplier(1f64))?
    };

    broadcast_tx(wallet, manager, tx).await;
    Ok(())
}

async fn burn(manager: &CommandManager<Arc<Wallet>>, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let amount = arguments.get_value("amount")?.to_number()?;
    let asset = arguments.get_value("asset")?.to_hash()?;
    let wallet = manager.get_data()?;
    manager.message(format!("Burning {} of {}", format_coin(amount), asset));

    let tx = {
        let storage = wallet.get_storage().read().await;
        wallet.create_transaction(&storage, TransactionType::Burn { asset, amount }, FeeBuilder::Multiplier(1f64))?
    };
    broadcast_tx(wallet, manager, tx).await;
    Ok(())
}

// Show current wallet address
async fn display_address(manager: &CommandManager<Arc<Wallet>>, _: ArgumentManager) -> Result<(), CommandError> {
    let wallet = manager.get_data()?;
    manager.message(format!("Wallet address: {}", wallet.get_address()));
    Ok(())
}

// Show current balance for specified asset
async fn balance(manager: &CommandManager<Arc<Wallet>>, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let asset = if arguments.has_argument("asset") {
        arguments.get_value("asset")?.to_hash()?
    } else {
        XELIS_ASSET // default asset selected is XELIS
    };

    let wallet = manager.get_data()?;
    let storage = wallet.get_storage().read().await;
    let balance = storage.get_balance_for(&asset).unwrap_or(0);
    manager.message(format!("Balance for asset {}: {}", asset, balance));

    Ok(())
}

// Show all transactions
const TXS_PER_PAGE: usize = 10;
async fn history(manager: &CommandManager<Arc<Wallet>>, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let page = if arguments.has_argument("page") {
        arguments.get_value("page")?.to_number()? as usize
    } else {
        1
    };

    if page == 0 {
        return Err(CommandError::InvalidArgument("Page must be greater than 0".to_string()));
    }

    let wallet = manager.get_data()?;
    let storage = wallet.get_storage().read().await;
    let mut transactions = storage.get_transactions()?;

    // if we don't have any txs, no need proceed further
    if transactions.is_empty() {
        manager.message("No transactions available");
        return Ok(())
    }

    // desc ordered
    transactions.sort_by(|a, b| b.get_topoheight().cmp(&a.get_topoheight()));
    let mut max_pages = transactions.len() / TXS_PER_PAGE;
    if transactions.len() % TXS_PER_PAGE != 0 {
        max_pages += 1;
    }

    if page > max_pages {
        return Err(CommandError::InvalidArgument(format!("Page must be less than maximum pages ({})", max_pages - 1)));
    }

    manager.message(format!("Transactions (total {}) page {}/{}:", transactions.len(), page, max_pages));
    for tx in transactions.iter().skip((page - 1) * TXS_PER_PAGE).take(TXS_PER_PAGE) {
        manager.message(format!("- {}", tx));
    }

    Ok(())
}

// Set your wallet in online mode
async fn online_mode(manager: &CommandManager<Arc<Wallet>>, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let wallet = manager.get_data()?;
    if wallet.is_online().await {
        manager.error("Wallet is already online");
    } else {
        let daemon_address = if arguments.has_argument("daemon_address") {
            arguments.get_value("daemon_address")?.to_string_value()?
        } else {
            DEFAULT_DAEMON_ADDRESS.to_string()
        };

        wallet.set_online_mode(&daemon_address).await.context("Couldn't enable online mode")?;
        manager.message("Wallet is now online");
    }
    Ok(())
}

// Set your wallet in offline mode
async fn offline_mode(manager: &CommandManager<Arc<Wallet>>, _: ArgumentManager) -> Result<(), CommandError> {
    let wallet = manager.get_data()?;
    if !wallet.is_online().await {
        manager.error("Wallet is already offline");
    } else {
        wallet.set_offline_mode().await.context("Error on offline mode")?;
        manager.message("Wallet is now offline");
    }
    Ok(())
}

// Show current wallet address
async fn rescan(manager: &CommandManager<Arc<Wallet>>, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let wallet = manager.get_data()?;
    let topoheight = if arguments.has_argument("topoheight") {
        arguments.get_value("topoheight")?.to_number()?
    } else {
        0
    };

    wallet.rescan(topoheight).await.context("error while restarting network handler")?;
    manager.message("Network handler has been restarted!");
    Ok(())
}

async fn seed(manager: &CommandManager<Arc<Wallet>>, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let wallet = manager.get_data()?;
    let language = if arguments.has_argument("language") {
        arguments.get_value("language")?.to_number()?
    } else {
        0
    };

    let seed = wallet.get_seed(language as usize)?;
    manager.message(format!("Seed: {}", seed));
    Ok(())
}

async fn nonce(manager: &CommandManager<Arc<Wallet>>, _: ArgumentManager) -> Result<(), CommandError> {
    let wallet = manager.get_data()?;
    let nonce = wallet.get_nonce().await;
    manager.message(format!("Nonce: {}", nonce));
    Ok(())
}

#[cfg(feature = "api_server")]
async fn stop_api_server(manager: &CommandManager<Arc<Wallet>>, _: ArgumentManager) -> Result<(), CommandError> {
    let wallet = manager.get_data()?;
    wallet.stop_api_server().await.context("Error while stopping API Server")?;
    manager.message("API Server has been stopped");
    Ok(())
}

#[cfg(feature = "api_server")]
async fn start_rpc_server(manager: &CommandManager<Arc<Wallet>>, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let wallet = manager.get_data()?;
    let bind_address = arguments.get_value("bind_address")?.to_string_value()?;
    let username = arguments.get_value("username")?.to_string_value()?;
    let password = arguments.get_value("password")?.to_string_value()?;

    let auth_config = Some(AuthConfig {
        username,
        password
    });

    wallet.enable_rpc_server(bind_address, auth_config).await.context("Error while enabling RPC Server")?;
    manager.message("RPC Server has been enabled");
    Ok(())
}

#[cfg(feature = "api_server")]
async fn start_xswd(manager: &CommandManager<Arc<Wallet>>, _: ArgumentManager) -> Result<(), CommandError> {
    let wallet = manager.get_data()?;
    if let Err(e) = wallet.enable_xswd().await {
        manager.error(format!("Error while enabling XSWD Server: {}", e));
    } else {
        manager.message("XSWD Server has been enabled");
    }

    Ok(())
}

// broadcast tx if possible
async fn broadcast_tx(wallet: &Wallet, manager: &CommandManager<Arc<Wallet>>, tx: Transaction) {
    let tx_hash = tx.hash();
    manager.message(format!("Transaction hash: {}", tx_hash));

    if wallet.is_online().await {
        if let Err(e) = wallet.submit_transaction(&tx).await {
            manager.error(format!("Couldn't submit transaction: {}", e));
            manager.error("You can try to rescan your balance with the command 'rescan'");
        } else {
            manager.message("Transaction submitted successfully!");
        }
    } else {
        manager.warn("You are currently offline, transaction cannot be send automatically. Please send it manually to the network.");
        manager.message(format!("Transaction in hex format: {}", tx.to_hex()));
    }
}