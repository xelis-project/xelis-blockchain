use std::{
    fs::File,
    io::Write,
    ops::ControlFlow,
    path::Path,
    sync::Arc,
    time::Duration
};
use anyhow::{Result, Context};
use log::{error, info};
use clap::Parser;
use serde::{Deserialize, Serialize};
use xelis_common::{
    tokio,
    async_handler,
    config::{
        COIN_DECIMALS,
        VERSION,
        XELIS_ASSET
    },
    crypto::{
        ecdlp,
        Address,
        Hashable
    },
    network::Network,
    prompt::{
        argument::{
            Arg,
            ArgType,
            ArgumentManager
        },
        command::{
            Command,
            CommandError,
            CommandHandler,
            CommandManager
        },
        LogLevel,
        Prompt,
        ModuleConfig,
        PromptError,
        Color
    },
    serializer::Serializer,
    transaction::{
        builder::{FeeBuilder, TransactionTypeBuilder, TransferBuilder},
        BurnPayload,
        Transaction
    },
    utils::{
        format_coin,
        format_xelis,
        from_coin
    }
};
use xelis_wallet::{
    wallet::{
        Wallet,
        RecoverOption
    },
    config::DIR_PATH,
    precomputed_tables,
};

#[cfg(feature = "network_handler")]
use xelis_wallet::config::DEFAULT_DAEMON_ADDRESS;

#[cfg(feature = "api_server")]
use {
    xelis_wallet::{
        api::{
            AuthConfig,
            PermissionResult,
            AppStateShared
        },
        wallet::XSWDEvent,
    },
    xelis_common::{
        rpc_server::RpcRequest,
        prompt::ShareablePrompt,
        tokio::{
            spawn_task,
            sync::mpsc::UnboundedReceiver
        }
    },
    anyhow::Error,
};

// This struct is used to configure the RPC Server
// In case we want to enable it instead of starting
// the XSWD Server
#[cfg(feature = "api_server")]
#[derive(Debug, clap::Args, Serialize, Deserialize)]
pub struct RPCConfig {
    /// RPC Server bind address
    #[clap(long)]
    rpc_bind_address: Option<String>,
    /// username for RPC authentication
    #[clap(long)]
    rpc_username: Option<String>,
    /// password for RPC authentication
    #[clap(long)]
    rpc_password: Option<String>,
    /// Number of threads to use for the RPC Server
    #[clap(long)]
    rpc_threads: Option<usize>
}

// Functions Helpers
fn default_daemon_address() -> String {
    DEFAULT_DAEMON_ADDRESS.to_owned()
}

fn default_precomputed_tables_l1() -> usize {
    precomputed_tables::L1_FULL
}

fn default_log_filename() -> String {
    String::from("xelis-wallet.log")
}

fn default_logs_path() -> String {
    String::from("logs/")
}

#[derive(Debug, clap::Args, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Daemon address to use
    #[cfg(feature = "network_handler")]
    #[clap(long, default_value_t = String::from(DEFAULT_DAEMON_ADDRESS))]
    #[serde(default = "default_daemon_address")]
    daemon_address: String,
    /// Disable online mode
    #[cfg(feature = "network_handler")]
    #[clap(long)]
    offline_mode: bool,
}

#[derive(Debug, clap::Args, Serialize, Deserialize)]
pub struct PrecomputedTablesConfig {
    /// L1 size for precomputed tables
    /// By default, it is set to 26 (L1_FULL)
    /// At each increment of 1, the size of the table is doubled
    /// L1_FULL = 26, L1_MEDIUM = 18, L1_LOW = 13
    #[clap(long, default_value_t = precomputed_tables::L1_FULL)]
    #[serde(default = "default_precomputed_tables_l1")]
    precomputed_tables_l1: usize,
    /// Set the path to use for precomputed tables
    /// 
    /// By default, it will be from current directory.
    #[clap(long)]
    precomputed_tables_path: Option<String>,
}

#[derive(Debug, clap::Args, Serialize, Deserialize)]
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
    /// If disabled, the log file will be named xelis-wallet.log instead of YYYY-MM-DD.xelis-wallet.log
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
    /// Log filename
    /// 
    /// By default filename is xelis-wallet.log.
    /// File will be stored in logs directory, this is only the filename, not the full path.
    /// Log file is rotated every day and has the format YYYY-MM-DD.xelis-wallet.log.
    #[clap(long, default_value_t = String::from("xelis-wallet.log"))]
    #[serde(default = "default_log_filename")]
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
pub struct Config {
    /// RPC Server configuration
    #[cfg(feature = "api_server")]
    #[structopt(flatten)]
    rpc: RPCConfig,
    /// Network Configuration
    #[structopt(flatten)]
    network_handler: NetworkConfig,
    /// Precopmuted tables configuration
    #[structopt(flatten)]
    precomputed_tables: PrecomputedTablesConfig,
    /// Log configuration
    #[structopt(flatten)]
    log: LogConfig,
    /// Set the path for wallet storage to open/create a wallet at this location
    #[clap(long)]
    wallet_path: Option<String>,
    /// Password used to open wallet
    #[clap(long)]
    password: Option<String>,
    /// Restore wallet using seed
    #[clap(long)]
    seed: Option<String>,
    /// Network selected for chain
    #[clap(long, value_enum, default_value_t = Network::Mainnet)]
    #[serde(default)]
    network: Network,
    /// XSWD Server configuration
    #[cfg(feature = "api_server")]
    #[clap(long)]
    #[serde(default)]
    enable_xswd: bool,
    /// Disable the history scan
    /// This will prevent syncing old TXs/blocks
    /// Only blocks / transactions caught by the network handler will be stored, not the old ones
    #[clap(long)]
    #[serde(default)]
    disable_history_scan: bool,
    /// Force the wallet to use a stable balance only during transactions creation.
    /// This will prevent the wallet to use unstable balance and prevent any orphaned transaction due to DAG reorg.
    /// This is only working if the wallet is in online mode.
    #[clap(long)]
    #[serde(default)]
    force_stable_balance: bool,
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

/// This struct is used to log the progress of the table generation
struct LogProgressTableGenerationReportFunction;

impl ecdlp::ProgressTableGenerationReportFunction for LogProgressTableGenerationReportFunction {
    fn report(&self, progress: f64, step: ecdlp::ReportStep) -> ControlFlow<()> {
        info!("Progress: {:.2}% on step {:?}", progress * 100.0, step);
        ControlFlow::Continue(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut config: Config = Config::parse();
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

    let log_config = &config.log;
    let prompt = Prompt::new(log_config.log_level, &log_config.logs_path, &log_config.filename_log, log_config.disable_file_logging, log_config.disable_file_log_date_based, log_config.disable_log_color, !log_config.disable_interactive_mode, log_config.logs_modules.clone(), log_config.file_log_level.unwrap_or(log_config.log_level))?;

    #[cfg(feature = "api_server")]
    {
        // Sanity check
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

    let command_manager = CommandManager::new(prompt.clone());
    command_manager.store_in_context(config.network)?;

    if let Some(path) = config.wallet_path.as_ref() {
        // read password from option or ask him
        let password = if let Some(password) = config.password.as_ref() {
            password.clone()
        } else {
            prompt.read_input(format!("Enter Password for '{}': ", path), true).await?
        };

        let precomputed_tables = precomputed_tables::read_or_generate_precomputed_tables(config.precomputed_tables.precomputed_tables_path.as_deref(), config.precomputed_tables.precomputed_tables_l1, LogProgressTableGenerationReportFunction, true).await?;
        let p = Path::new(path);
        let wallet = if p.exists() && p.is_dir() && Path::new(&format!("{}/db", path)).exists() {
            info!("Opening wallet {}", path);
            Wallet::open(path, &password, config.network, precomputed_tables)?
        } else {
            info!("Creating a new wallet at {}", path);
            Wallet::create(path, &password, config.seed.as_deref().map(RecoverOption::Seed), config.network, precomputed_tables)?
        };

        command_manager.register_default_commands()?;

        apply_config(config, &wallet, #[cfg(feature = "api_server")] &prompt).await;
        setup_wallet_command_manager(wallet, &command_manager).await?;
    } else {
        register_default_commands(&command_manager).await?;
    }

    if let Err(e) = prompt.start(Duration::from_millis(1000), Box::new(async_handler!(prompt_message_builder)), Some(&command_manager)).await {
        error!("Error while running prompt: {}", e);
    }

    if let Ok(context) = command_manager.get_context().lock() {
        if let Ok(wallet) = context.get::<Arc<Wallet>>() {
            wallet.close().await;
        }
    }

    Ok(())
}

async fn register_default_commands(manager: &CommandManager) -> Result<(), CommandError> {
    manager.add_command(Command::new("open", "Open a wallet", CommandHandler::Async(async_handler!(open_wallet))))?;
    manager.add_command(Command::new("create", "Create a new wallet", CommandHandler::Async(async_handler!(create_wallet))))?;
    manager.add_command(Command::new("recover_seed", "Recover a wallet using a seed", CommandHandler::Async(async_handler!(recover_seed))))?;
    manager.add_command(Command::new("recover_private_key", "Recover a wallet using a private key", CommandHandler::Async(async_handler!(recover_private_key))))?;

    manager.register_default_commands()?;
    // Display available commands
    manager.display_commands()?;

    Ok(())
}

#[cfg(feature = "api_server")]
// This must be run in a separate task
async fn xswd_handler(mut receiver: UnboundedReceiver<XSWDEvent>, prompt: ShareablePrompt) {
    while let Some(event) = receiver.recv().await {
        match event {
            XSWDEvent::CancelRequest(_, callback) => {
                let res = prompt.cancel_read_input().await;
                if callback.send(res).is_err() {
                    error!("Error while sending cancel response back to XSWD");
                }
            },
            XSWDEvent::RequestApplication(app_state, signed, callback) => {
                let prompt = prompt.clone();
                spawn_task("xswd-request", async move {
                    let res = xswd_handle_request_application(&prompt, app_state, signed).await;
                    if callback.send(res).is_err() {
                        error!("Error while sending application response back to XSWD");
                    }
                });
            },
            XSWDEvent::RequestPermission(app_state, request, callback) => {
                let res = xswd_handle_request_permission(&prompt, app_state, request).await;
                if callback.send(res).is_err() {
                    error!("Error while sending permission response back to XSWD");
                }
            }
        };
    }
}

#[cfg(feature = "api_server")]
async fn xswd_handle_request_application(prompt: &ShareablePrompt, app_state: AppStateShared, signed: bool) -> Result<PermissionResult, Error> {
    let mut message = format!("XSWD: Allow application {} ({}) to access your wallet\r\n(Y/N): ", app_state.get_name(), app_state.get_id());
    if signed {
        message = prompt.colorize_str(Color::BrightYellow, "NOTE: Application authorizaion was already approved previously.\r\n") + &message;
    }
    let accepted = prompt.read_valid_str_value(prompt.colorize_string(Color::Blue, &message), vec!["y", "n"]).await? == "y";
    if accepted {
        Ok(PermissionResult::Allow)
    } else {
        Ok(PermissionResult::Deny)
    }
}

#[cfg(feature = "api_server")]
async fn xswd_handle_request_permission(prompt: &ShareablePrompt, app_state: AppStateShared, request: RpcRequest) -> Result<PermissionResult, Error> {
    let params = if let Some(params) = request.params {
        params.to_string()
    } else {
        "".to_string()
    };

    let message = format!(
        "XSWD: Request from {}: {}\r\nParams: {}\r\nDo you want to allow this request ?\r\n([A]llow / [D]eny / [AA] Always Allow / [AD] Always Deny): ",
        app_state.get_name(),
        request.method,
        params
    );

    let answer = prompt.read_valid_str_value(prompt.colorize_string(Color::Blue, &message), vec!["a", "d", "aa", "ad"]).await?;
    Ok(match answer.as_str() {
        "a" => PermissionResult::Allow,
        "d" => PermissionResult::Deny,
        "aa" => PermissionResult::AlwaysAllow,
        "ad" => PermissionResult::AlwaysDeny,
        _ => unreachable!()
    })
}

// Apply the config passed in params
async fn apply_config(config: Config, wallet: &Arc<Wallet>, #[cfg(feature = "api_server")] prompt: &ShareablePrompt) {
    #[cfg(feature = "network_handler")]
    if !config.network_handler.offline_mode {
        info!("Trying to connect to daemon at '{}'", config.network_handler.daemon_address);
        if let Err(e) = wallet.set_online_mode(&config.network_handler.daemon_address, true).await {
            error!("Couldn't connect to daemon: {}", e);
            info!("You can activate online mode using 'online_mode [daemon_address]'");
        } else {
            info!("Online mode enabled");
        }
    }

    wallet.set_history_scan(!config.disable_history_scan);
    wallet.set_stable_balance(config.force_stable_balance);

    #[cfg(feature = "api_server")]
    {
        if config.enable_xswd && config.rpc.rpc_bind_address.is_some() {
            error!("Invalid parameters configuration: RPC Server and XSWD cannot be enabled at the same time");
            return;
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
            if let Err(e) = wallet.enable_rpc_server(address, auth_config, config.rpc.rpc_threads).await {
                error!("Error while enabling RPC Server: {}", e);
            }
        } else if config.enable_xswd {
            match wallet.enable_xswd().await {
                Ok(receiver) => {
                    // Only clone when its necessary
                    let prompt = prompt.clone();
                    spawn_task("xswd-handler", xswd_handler(receiver, prompt));
                },
                Err(e) => error!("Error while enabling XSWD Server: {}", e)
            };
        }
    }
}

// Function to build the CommandManager when a wallet is open
async fn setup_wallet_command_manager(wallet: Arc<Wallet>, command_manager: &CommandManager) -> Result<(), CommandError> {
    // Delete commands for opening a wallet
    command_manager.remove_command("open")?;
    command_manager.remove_command("recover")?;
    command_manager.remove_command("create")?;

    // Add wallet commands
    command_manager.add_command(Command::new(
        "change_password",
        "Set a new password to open your wallet",
        CommandHandler::Async(async_handler!(change_password))
    ))?;
    command_manager.add_command(Command::with_optional_arguments(
        "transfer",
        "Send asset to a specified address",
        vec![
            Arg::new("asset", ArgType::Hash),
            Arg::new("address", ArgType::String),
            Arg::new("amount", ArgType::String),
            Arg::new("confirm", ArgType::Bool)
        ],
        CommandHandler::Async(async_handler!(transfer))
    ))?;
    command_manager.add_command(Command::with_optional_arguments(
        "transfer_all",
        "Send all your asset balance to a specified address",
        vec![
            Arg::new("asset", ArgType::Hash),
            Arg::new("address", ArgType::String),
            Arg::new("confirm", ArgType::Bool)
        ],
        CommandHandler::Async(async_handler!(transfer_all))
    ))?;
    command_manager.add_command(Command::with_optional_arguments(
        "burn",
        "Burn amount of asset",
        vec![
            Arg::new("asset", ArgType::Hash),
            Arg::new("amount", ArgType::String),
            Arg::new("confirm", ArgType::Bool)
        ],    
        CommandHandler::Async(async_handler!(burn))
    ))?;
    command_manager.add_command(Command::new(
        "display_address",
        "Show your wallet address",
        CommandHandler::Async(async_handler!(display_address))
    ))?;
    command_manager.add_command(Command::with_optional_arguments(
        "balance",
        "List all non-zero balances or show the selected one",
        vec![Arg::new("asset", ArgType::Hash)],
        CommandHandler::Async(async_handler!(balance))
    ))?;
    command_manager.add_command(Command::with_optional_arguments(
        "history",
        "Show all your transactions",
        vec![Arg::new("page", ArgType::Number)],
        CommandHandler::Async(async_handler!(history))
    ))?;
    command_manager.add_command(Command::with_optional_arguments(
        "seed",
        "Show seed of selected language",
        vec![Arg::new("language", ArgType::Number)],
        CommandHandler::Async(async_handler!(seed))
    ))?;
    command_manager.add_command(Command::new(
        "nonce",
        "Show current nonce",
        CommandHandler::Async(async_handler!(nonce))
    ))?;
    command_manager.add_command(Command::new(
        "set_nonce",
        "Set new nonce",
        CommandHandler::Async(async_handler!(set_nonce))
    ))?;
    command_manager.add_command(Command::new(
        "logout",
        "Logout from existing wallet",
        CommandHandler::Async(async_handler!(logout)))
    )?;
    command_manager.add_command(Command::new(
        "clear_tx_cache",
        "Clear the current TX cache",
        CommandHandler::Async(async_handler!(clear_tx_cache))
    ))?;
    command_manager.add_command(Command::with_required_arguments(
        "export_transactions",
        "Export all your transactions in a CSV file",
        vec![Arg::new("filename", ArgType::String)],
        CommandHandler::Async(async_handler!(export_transactions_csv))
    ))?;

    #[cfg(feature = "network_handler")]
    {
        command_manager.add_command(Command::with_optional_arguments(
            "online_mode",
            "Set your wallet in online mode",
            vec![Arg::new("daemon_address", ArgType::String)],
            CommandHandler::Async(async_handler!(online_mode))
        ))?;
        command_manager.add_command(Command::new(
            "offline_mode",
            "Set your wallet in offline mode",
            CommandHandler::Async(async_handler!(offline_mode))
        ))?;
        command_manager.add_command(Command::with_optional_arguments(
            "rescan",
            "Rescan balance and transactions",
            vec![Arg::new("topoheight", ArgType::Number)],
            CommandHandler::Async(async_handler!(rescan))
        ))?;
    }

    #[cfg(feature = "api_server")]
    {
        // Unauthenticated RPC Server can only be created by launch arguments option
        command_manager.add_command(Command::with_required_arguments(
            "start_rpc_server",
            "Start the RPC Server",
            vec![
                Arg::new("bind_address", ArgType::String),
                Arg::new("username", ArgType::String),
                Arg::new("password", ArgType::String)
            ], CommandHandler::Async(async_handler!(start_rpc_server))))?;

        command_manager.add_command(Command::new(
            "start_xswd",
            "Start the XSWD Server",
            CommandHandler::Async(async_handler!(start_xswd)))
        )?;

        // Stop API Server (RPC or XSWD)
        command_manager.add_command(Command::new(
            "stop_api_server",
            "Stop the API (XSWD/RPC) Server",
            CommandHandler::Async(async_handler!(stop_api_server)))
        )?;
    }

    let mut context = command_manager.get_context().lock()?;
    context.store(wallet);

    command_manager.display_commands()
}

// Function passed as param to prompt to build the prompt message shown
async fn prompt_message_builder(prompt: &Prompt, command_manager: Option<&CommandManager>) -> Result<String, PromptError> {
    if let Some(manager) = command_manager {
        let context = manager.get_context().lock()?;
        if let Ok(wallet) = context.get::<Arc<Wallet>>() {
            let network = wallet.get_network();

            let addr_str = {
                let addr = &wallet.get_address().to_string()[..8];
                prompt.colorize_str(Color::Yellow, addr)
            };
    
            let storage = wallet.get_storage().read().await;
            let topoheight_str = format!(
                "{}: {}",
                prompt.colorize_str(Color::Yellow, "TopoHeight"),
                prompt.colorize_string(Color::Green, &format!("{}", storage.get_synced_topoheight().unwrap_or(0)))
            );
            let balance = format!(
                "{}: {}",
                prompt.colorize_str(Color::Yellow, "Balance"),
                prompt.colorize_string(Color::Green, &format_xelis(storage.get_plaintext_balance_for(&XELIS_ASSET).await.unwrap_or(0))),
            );
            let status = if wallet.is_online().await {
                prompt.colorize_str(Color::Green, "Online")
            } else {
                prompt.colorize_str(Color::Red, "Offline")
            };
            let network_str = if !network.is_mainnet() {
                format!(
                    "{} ",
                    prompt.colorize_string(Color::Red, &network.to_string())
                )
            } else { "".into() };
    
            return Ok(
                format!(
                    "{} | {} | {} | {} | {} {}{} ",
                    prompt.colorize_str(Color::Blue, "XELIS Wallet"),
                    addr_str,
                    topoheight_str,
                    balance,
                    status,
                    network_str,
                    prompt.colorize_str(Color::BrightBlack, ">>")
                )
            )
        }
    }

    Ok(
        format!(
            "{} {} ",
            prompt.colorize_str(Color::Blue, "XELIS Wallet"),
            prompt.colorize_str(Color::BrightBlack, ">>")
        )
    )
}

// Open a wallet based on the wallet name and its password
async fn open_wallet(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    let prompt = manager.get_prompt();
    let config: Config = Config::parse();
    let dir = if let Some(path) = config.wallet_path.as_ref() {
        path.clone()
    } else {
        let name = prompt.read_input("Wallet name: ", false)
            .await.context("Error while reading wallet name")?;

        if name.is_empty() {
            manager.error("Wallet name cannot be empty");
            return Ok(())
        }
        format!("{}{}", DIR_PATH, name)
    };

    if !Path::new(&dir).is_dir() {
        manager.message("No wallet found with this name");
        return Ok(())
    }

    let password = prompt.read_input("Password: ", true)
        .await.context("Error while reading wallet password")?;

    let wallet = {
        let context = manager.get_context().lock()?;
        let network = context.get::<Network>()?;
        let precomputed_tables = precomputed_tables::read_or_generate_precomputed_tables(config.precomputed_tables.precomputed_tables_path.as_deref(), config.precomputed_tables.precomputed_tables_l1, LogProgressTableGenerationReportFunction, true).await?;
        Wallet::open(&dir, &password, *network, precomputed_tables)?
    };

    manager.message("Wallet sucessfully opened");
    apply_config(config, &wallet, #[cfg(feature = "api_server")] prompt).await;

    setup_wallet_command_manager(wallet, manager).await?;

    Ok(())
}

// Create a wallet by requesting name, password
async fn create_wallet(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    let prompt = manager.get_prompt();
    let config: Config = Config::parse();
    let dir = if let Some(path) = config.wallet_path.as_ref() {
        path.clone()
    } else {
        let name = prompt.read_input("Wallet name: ", false)
            .await.context("Error while reading wallet name")?;

        if name.is_empty() {
            manager.error("Wallet name cannot be empty");
            return Ok(())
        }
        format!("{}{}", DIR_PATH, name)
    };

    if !Path::new(&dir).is_dir() {
        manager.message("No wallet found with this name");
        return Ok(())
    }

    // ask and verify password
    let password = prompt.read_input("Password: ", true)
        .await.context("Error while reading password")?;
    let confirm_password = prompt.read_input("Confirm Password: ", true)
        .await.context("Error while reading password")?;

    if password != confirm_password {
        manager.message("Confirm password doesn't match password");        
        return Ok(())
    }

    let wallet = {
        let context = manager.get_context().lock()?;
        let network = context.get::<Network>()?;
        let precomputed_tables = precomputed_tables::read_or_generate_precomputed_tables(config.precomputed_tables.precomputed_tables_path.as_deref(), precomputed_tables::L1_FULL, LogProgressTableGenerationReportFunction, true).await?;
        Wallet::create(&dir, &password, None, *network, precomputed_tables)?
    };
 
    manager.message("Wallet sucessfully created");
    apply_config(config, &wallet, #[cfg(feature = "api_server")] prompt).await;

    // Display the seed in prompt
    {
        let seed = wallet.get_seed(0)?; // TODO language index
        prompt.read_input(format!("Seed: {}\r\nPress ENTER to continue", seed), false)
            .await.context("Error while displaying seed")?;
    }

    setup_wallet_command_manager(wallet, manager).await?;

    Ok(())
}

// Recover a wallet by requesting its seed or private key, name and password
async fn recover_wallet(manager: &CommandManager, _: ArgumentManager, seed: bool) -> Result<(), CommandError> {
    let prompt = manager.get_prompt();
    let config: Config = Config::parse();
    let dir = if let Some(path) = config.wallet_path.as_ref() {
        path.clone()
    } else {
        let name = prompt.read_input("Wallet name: ", false)
            .await.context("Error while reading wallet name")?;

        if name.is_empty() {
            manager.error("Wallet name cannot be empty");
            return Ok(())
        }
        format!("{}{}", DIR_PATH, name)
    };

    if Path::new(&dir).is_dir() {
        manager.message("Wallet already exists with this name");
        return Ok(())
    }

    let content = if seed {
        let seed = prompt.read_input("Seed: ", false)
            .await.context("Error while reading seed")?;
    
        let words_count = seed.split_whitespace().count();
        if words_count != 25 && words_count != 24 {
            manager.error("Seed must be 24 or 25 (checksum) words long");
            return Ok(())
        }
        seed
    } else {
        let private_key = prompt.read_input("Private Key: ", false)
            .await.context("Error while reading private key")?;
    
        if private_key.len() != 64 {
            manager.error("Private key must be 64 characters long");
            return Ok(())
        }
        private_key
    };

    // ask and verify password
    let password = prompt.read_input("Password: ", true)
        .await.context("Error while reading password")?;
    let confirm_password = prompt.read_input("Confirm Password: ", true)
        .await.context("Error while reading password")?;

    if password != confirm_password {
        manager.message("Confirm password doesn't match password");        
        return Ok(())
    }

    let wallet = {
        let context = manager.get_context().lock()?;
        let network = context.get::<Network>()?;
        let precomputed_tables = precomputed_tables::read_or_generate_precomputed_tables(config.precomputed_tables.precomputed_tables_path.as_deref(), config.precomputed_tables.precomputed_tables_l1, LogProgressTableGenerationReportFunction, true).await?;

        let recover = if seed {
            RecoverOption::Seed(&content)
        } else {
            RecoverOption::PrivateKey(&content)
        };
        Wallet::create(&dir, &password, Some(recover), *network, precomputed_tables)?
    };

    manager.message("Wallet sucessfully recovered");
    apply_config(config, &wallet, #[cfg(feature = "api_server")] prompt).await;

    setup_wallet_command_manager(wallet, manager).await?;

    Ok(())
}

async fn recover_seed(manager: &CommandManager, args: ArgumentManager) -> Result<(), CommandError> {
    recover_wallet(manager, args, true).await
}

async fn recover_private_key(manager: &CommandManager, args: ArgumentManager) -> Result<(), CommandError> {
    recover_wallet(manager, args, false).await
}


// Change wallet password
async fn change_password(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let wallet: &Arc<Wallet> = context.get()?;

    let prompt = manager.get_prompt();

    let old_password = prompt.read_input(prompt.colorize_str(Color::BrightRed, "Current Password: "), true)
        .await
        .context("Error while asking old password")?;

    let new_password = prompt.read_input(prompt.colorize_str(Color::BrightRed, "New Password: "), true)
        .await
        .context("Error while asking new password")?;

    manager.message("Changing password...");
    wallet.set_password(&old_password, &new_password).await?;
    manager.message("Your password has been changed!");
    Ok(())
}

// Create a new transfer to a specified address
async fn transfer(manager: &CommandManager, mut args: ArgumentManager) -> Result<(), CommandError> {
    let prompt = manager.get_prompt();
    let context = manager.get_context().lock()?;
    let wallet: &Arc<Wallet> = context.get()?;

    // read address
    let str_address = if args.has_argument("address") {
        args.get_value("address")?.to_string_value()?
    } else {
        prompt.read_input(
            prompt.colorize_str(Color::Green, "Address: "),
            false
        ).await.context("Error while reading address")?
    };
    let address = Address::from_string(&str_address).context("Invalid address")?;

    let asset = if args.has_argument("asset") {
        args.get_value("asset")?.to_hash()?
    } else {
        prompt.read_hash(
            prompt.colorize_str(Color::Green, "Asset (default XELIS): ")
        ).await.unwrap_or(XELIS_ASSET)
    };

    let (max_balance, decimals) = {
        let storage = wallet.get_storage().read().await;
        let balance = storage.get_plaintext_balance_for(&asset).await.unwrap_or(0);
        let decimals = storage.get_asset_decimals(&asset).unwrap_or(COIN_DECIMALS);
        (balance, decimals)
    };

    // read amount
    let amount = if args.has_argument("amount") {
        args.get_value("amount")?.to_string_value()?
    } else {
        prompt.read(
            prompt.colorize_string(Color::Green, &format!("Amount (max: {}): ", format_coin(max_balance, decimals)))
        ).await.context("Error while reading amount")?
    };

    let amount = from_coin(amount, decimals).context("Invalid amount")?;
    manager.message(format!("Sending {} of {} to {}", format_coin(amount, decimals), asset, address.to_string()));

    if !args.get_flag("confirm")? && !prompt.ask_confirmation().await.context("Error while confirming action")? {
        manager.message("Transaction has been aborted");
        return Ok(())
    }

    manager.message("Building transaction...");

    let transfer = TransferBuilder {
        destination: address,
        amount,
        asset,
        extra_data: None
    };
    let tx = match wallet.create_transaction(TransactionTypeBuilder::Transfers(vec![transfer]), FeeBuilder::default()).await {
        Ok(tx) => tx,
        Err(e) => {
            manager.error(&format!("Error while creating transaction: {}", e));
            return Ok(())
        }
    };

    broadcast_tx(wallet, manager, tx).await;
    Ok(())
}


// Send the whole balance to a specified address
async fn transfer_all(manager: &CommandManager, mut args: ArgumentManager) -> Result<(), CommandError> {
    let prompt = manager.get_prompt();
    let context = manager.get_context().lock()?;
    let wallet: &Arc<Wallet> = context.get()?;

    // read address
    let str_address = if args.has_argument("address") {
        args.get_value("address")?.to_string_value()?
    } else {
        prompt.read_input(
            prompt.colorize_str(Color::Green, "Address: "),
            false
        ).await.context("Error while reading address")?
    };
    let address = Address::from_string(&str_address).context("Invalid address")?;

    let mut asset = args.get_value("asset").and_then(|v| v.to_hash()).ok();
    if asset.is_none() {
        asset = prompt.read_hash(
           prompt.colorize_str(Color::Green, "Asset (default XELIS): ")
       ).await.ok();
    }

    let asset = asset.unwrap_or(XELIS_ASSET);
    let (mut amount, decimals) = {
        let storage = wallet.get_storage().read().await;
        let amount = storage.get_plaintext_balance_for(&asset).await.unwrap_or(0);
        let decimals = storage.get_asset_decimals(&asset).unwrap_or(COIN_DECIMALS);
        (amount, decimals)
    };

    let transfer = TransferBuilder {
        destination: address.clone(),
        amount,
        asset: asset.clone(),
        extra_data: None
    };
    let tx_type = TransactionTypeBuilder::Transfers(vec![transfer]);
    let estimated_fees = wallet.estimate_fees(tx_type.clone()).await.context("Error while estimating fees")?;

    if asset == XELIS_ASSET {
        amount = amount.checked_sub(estimated_fees).context("Insufficient balance to pay fees")?;
    }

    manager.message(format!("Sending {} of {} to {} (fees: {})", format_coin(amount, decimals), asset, address.to_string(), format_xelis(estimated_fees)));

    if !args.get_flag("confirm")? && !prompt.ask_confirmation().await.context("Error while confirming action")? {
        manager.message("Transaction has been aborted");
        return Ok(())
    }

    let transfer = TransferBuilder {
        destination: address,
        amount,
        asset,
        extra_data: None
    };
    let tx_type = TransactionTypeBuilder::Transfers(vec![transfer]);

    manager.message("Building transaction...");

    let tx = wallet.create_transaction(tx_type, FeeBuilder::default()).await
        .context("Error while creating transaction")?;

    broadcast_tx(wallet, manager, tx).await;
    Ok(())
}

async fn burn(manager: &CommandManager, mut args: ArgumentManager) -> Result<(), CommandError> {
    let prompt = manager.get_prompt();
    let context = manager.get_context().lock()?;
    let wallet: &Arc<Wallet> = context.get()?;

    let asset = if args.has_argument("asset") {
        args.get_value("asset")?.to_hash()?
    } else {
        prompt.read_hash(
            prompt.colorize_str(Color::Green, "Asset (default XELIS): ")
        ).await.unwrap_or(XELIS_ASSET)
    };

    let (max_balance, decimals) = {
        let storage = wallet.get_storage().read().await;
        let balance = storage.get_plaintext_balance_for(&asset).await.unwrap_or(0);
        let decimals = storage.get_asset_decimals(&asset).unwrap_or(COIN_DECIMALS);
        (balance, decimals)
    };

    // read amount
    let amount = if args.has_argument("amount") {
        args.get_value("amount")?.to_string_value()?
    } else {
        prompt.read(
            prompt.colorize_string(Color::Green, &format!("Amount (max: {}): ", format_coin(max_balance, decimals)))
        ).await.context("Error while reading amount")?
    };

    let amount = from_coin(amount, decimals).context("Invalid amount")?;
    manager.message(format!("Burning {} of {}", format_coin(amount, decimals), asset));
    if !args.get_flag("confirm")? && !prompt.ask_confirmation().await.context("Error while confirming action")? {
        manager.message("Transaction has been aborted");
        return Ok(())
    }

    let payload = BurnPayload {
        amount,
        asset
    };

    manager.message("Building transaction...");

    let tx = wallet.create_transaction(TransactionTypeBuilder::Burn(payload), FeeBuilder::Multiplier(1f64)).await
        .context("Error while creating burn transaction")?;

    broadcast_tx(wallet, manager, tx).await;
    Ok(())
}

// Show current wallet address
async fn display_address(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let wallet: &Arc<Wallet> = context.get()?;
    manager.message(format!("Wallet address: {}", wallet.get_address()));
    Ok(())
}

// Show current balance for specified asset or list all non-zero balances
async fn balance(manager: &CommandManager, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let wallet: &Arc<Wallet> = context.get()?;
    let storage = wallet.get_storage().read().await;

    if arguments.has_argument("asset") {
        let asset = arguments.get_value("asset")?.to_hash()?;
        let balance = storage.get_plaintext_balance_for(&asset).await.unwrap_or(0);
        let decimals = storage.get_asset_decimals(&asset).unwrap_or(0);
        manager.message(format!("Balance for asset {}: {}", asset, format_coin(balance, decimals)));
    } else {
        for (asset, decimals) in storage.get_assets_with_decimals().await? {
            let balance = storage.get_plaintext_balance_for(&asset).await.unwrap_or(0);
            if balance > 0 {
                manager.message(format!("Balance for asset {}: {}", asset, format_coin(balance, decimals)));
            }
        }
    }

    Ok(())
}

// Show all transactions
const TXS_PER_PAGE: usize = 10;
async fn history(manager: &CommandManager, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let page = if arguments.has_argument("page") {
        arguments.get_value("page")?.to_number()? as usize
    } else {
        1
    };

    if page == 0 {
        return Err(CommandError::InvalidArgument("Page must be greater than 0".to_string()));
    }

    let context = manager.get_context().lock()?;
    let wallet: &Arc<Wallet> = context.get()?;
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
        manager.message(format!("- {}", tx.summary(wallet.get_network().is_mainnet(), &*storage)?));
    }

    Ok(())
}

async fn export_transactions_csv(manager: &CommandManager, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let filename = arguments.get_value("filename")?.to_string_value()?;
    let context = manager.get_context().lock()?;
    let wallet: &Arc<Wallet> = context.get()?;
    let storage = wallet.get_storage().read().await;
    let transactions = storage.get_transactions()?;
    let mut file = File::create(&filename).context("Error while creating CSV file")?;

    wallet.export_transactions_in_csv(transactions, &mut file).context("Error while exporting transactions to CSV")?;

    // writer.flush().context("Error while flushing CSV file")?;
    manager.message(format!("Transactions have been exported to {}", filename));
    Ok(())
}

async fn clear_tx_cache(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let wallet: &Arc<Wallet> = context.get()?;
    let mut storage = wallet.get_storage().write().await;
    storage.clear_tx_cache();
    manager.message("Transaction cache has been cleared");
    Ok(())
}

// Set your wallet in online mode
#[cfg(feature = "network_handler")]
async fn online_mode(manager: &CommandManager, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let wallet: &Arc<Wallet> = context.get()?;
    if wallet.is_online().await {
        manager.error("Wallet is already online");
    } else {
        let daemon_address = if arguments.has_argument("daemon_address") {
            arguments.get_value("daemon_address")?.to_string_value()?
        } else {
            DEFAULT_DAEMON_ADDRESS.to_string()
        };

        wallet.set_online_mode(&daemon_address, true).await.context("Couldn't enable online mode")?;
        manager.message("Wallet is now online");
    }
    Ok(())
}

// Set your wallet in offline mode
#[cfg(feature = "network_handler")]
async fn offline_mode(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let wallet: &Arc<Wallet> = context.get()?;
    if !wallet.is_online().await {
        manager.error("Wallet is already offline");
    } else {
        wallet.set_offline_mode().await.context("Error on offline mode")?;
        manager.message("Wallet is now offline");
    }
    Ok(())
}

// Show current wallet address
#[cfg(feature = "network_handler")]
async fn rescan(manager: &CommandManager, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let wallet: &Arc<Wallet> = context.get()?;
    let topoheight = if arguments.has_argument("topoheight") {
        arguments.get_value("topoheight")?.to_number()?
    } else {
        0
    };

    if let Err(e) = wallet.rescan(topoheight, true).await {
        manager.error(format!("Error while rescanning: {}", e));
    } else {
        manager.message("Network handler has been restarted!");
    }
    Ok(())
}

async fn seed(manager: &CommandManager, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let wallet: &Arc<Wallet> = context.get()?;
    let prompt =  manager.get_prompt();

    let password = prompt.read_input("Password: ", true)
        .await.context("Error while reading password")?;
    // check if password is valid
    wallet.is_valid_password(&password).await?;

    let language = if arguments.has_argument("language") {
        arguments.get_value("language")?.to_number()?
    } else {
        0
    };

    let seed = wallet.get_seed(language as usize)?;
    prompt.read_input(
        prompt.colorize_string(Color::Green, &format!("Seed: {}\r\nPress ENTER to continue", seed)),
        false
    ).await.context("Error while printing seed")?;
    Ok(())
}

async fn nonce(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let wallet: &Arc<Wallet> = context.get()?;
    let storage = wallet.get_storage().read().await;
    let nonce = storage.get_nonce()?;
    let unconfirmed_nonce = storage.get_unconfirmed_nonce();
    manager.message(format!("Nonce: {}", nonce));
    if nonce != unconfirmed_nonce {
        manager.message(format!("Unconfirmed nonce: {}", unconfirmed_nonce));
    }

    Ok(())
}

async fn set_nonce(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    let value = manager.get_prompt().read("New Nonce: ".to_string()).await
        .context("Error while reading new nonce to set")?;

    let context = manager.get_context().lock()?;
    let wallet: &Arc<Wallet> = context.get()?;
    let mut storage = wallet.get_storage().write().await;
    storage.set_nonce(value)?;
    storage.clear_tx_cache();

    manager.message(format!("New nonce is: {}", value));
    Ok(())
}

async fn logout(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    {
        let context = manager.get_context().lock()?;
        let wallet: &Arc<Wallet> = context.get()?;
        wallet.close().await;
    }

    manager.remove_all_commands().context("Error while removing all commands")?;
    manager.remove_from_context::<Arc<Wallet>>()?;

    register_default_commands(manager).await?;
    manager.message("Wallet has been closed");

    Ok(())
}

#[cfg(feature = "api_server")]
async fn stop_api_server(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let wallet: &Arc<Wallet> = context.get()?;
    wallet.stop_api_server().await.context("Error while stopping API Server")?;
    manager.message("API Server has been stopped");
    Ok(())
}

#[cfg(feature = "api_server")]
async fn start_rpc_server(manager: &CommandManager, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let wallet: &Arc<Wallet> = context.get()?;
    let bind_address = arguments.get_value("bind_address")?.to_string_value()?;
    let username = arguments.get_value("username")?.to_string_value()?;
    let password = arguments.get_value("password")?.to_string_value()?;

    let auth_config = Some(AuthConfig {
        username,
        password
    });

    wallet.enable_rpc_server(bind_address, auth_config, None).await.context("Error while enabling RPC Server")?;
    manager.message("RPC Server has been enabled");
    Ok(())
}

#[cfg(feature = "api_server")]
async fn start_xswd(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let wallet: &Arc<Wallet> = context.get()?;
    match wallet.enable_xswd().await {
        Ok(receiver) => {
            let prompt = manager.get_prompt().clone();
            spawn_task("xswd", xswd_handler(receiver, prompt));
            manager.message("XSWD Server has been enabled");
        },
        Err(e) => manager.error(format!("Error while enabling XSWD Server: {}", e))
    };

    Ok(())
}

// broadcast tx if possible
// submit_transaction increase the local nonce in storage in case of success
async fn broadcast_tx(wallet: &Wallet, manager: &CommandManager, tx: Transaction) {
    let tx_hash = tx.hash();
    manager.message(format!("Transaction hash: {}", tx_hash));

    if wallet.is_online().await {
        if let Err(e) = wallet.submit_transaction(&tx).await {
            manager.error(format!("Couldn't submit transaction: {}", e));
            manager.error("You can try to rescan your balance with the command 'rescan'");

            // Maybe cache is corrupted, clear it
            let mut storage = wallet.get_storage().write().await;
            storage.clear_tx_cache();
            storage.delete_unconfirmed_balances().await;
        } else {
            manager.message("Transaction submitted successfully!");
        }
    } else {
        manager.warn("You are currently offline, transaction cannot be send automatically. Please send it manually to the network.");
        manager.message(format!("Transaction in hex format: {}", tx.to_hex()));
    }
}