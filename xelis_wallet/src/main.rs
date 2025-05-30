use std::{
    fs::File,
    io::Write,
    path::Path,
    sync::Arc,
    time::Duration
};
use anyhow::{Result, Context};
use indexmap::IndexSet;
use log::{error, info};
use clap::Parser;
use xelis_common::{
    async_handler,
    config::{
        init,
        XELIS_ASSET
    },
    crypto::{
        Address,
        Hash,
        Hashable,
        Signature,
        HASH_SIZE
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
        Color,
        Prompt,
        PromptError
    },
    serializer::Serializer,
    tokio,
    transaction::{
        builder::{FeeBuilder, MultiSigBuilder, TransactionTypeBuilder, TransferBuilder},
        multisig::{MultiSig, SignatureId},
        BurnPayload,
        MultiSigPayload,
        Transaction,
        TxVersion
    },
    utils::{
        format_coin,
        format_xelis,
        from_coin
    }
};
use xelis_wallet::{
    config::{Config, LogProgressTableGenerationReportFunction, DIR_PATH},
    precomputed_tables,
    wallet::{
        RecoverOption,
        Wallet
    }
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

const ELEMENTS_PER_PAGE: usize = 10;

#[tokio::main]
async fn main() -> Result<()> {
    init();

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
        log_config.file_log_level.unwrap_or(log_config.log_level),
        !log_config.disable_ascii_art,
        log_config.datetime_format.clone(),
    )?;

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
            Wallet::open(path, &password, config.network, precomputed_tables, config.n_decryption_threads, config.network_concurrency)?
        } else {
            info!("Creating a new wallet at {}", path);
            Wallet::create(path, &password, config.seed.as_deref().map(RecoverOption::Seed), config.network, precomputed_tables, config.n_decryption_threads, config.network_concurrency).await?
        };

        command_manager.register_default_commands()?;

        apply_config(config, &wallet, #[cfg(feature = "api_server")] &prompt).await;
        setup_wallet_command_manager(wallet, &command_manager).await?;
    } else {
        register_default_commands(&command_manager).await?;
    }

    if let Err(e) = prompt.start(Duration::from_millis(1000), Box::new(async_handler!(prompt_message_builder)), Some(&command_manager)).await {
        error!("Error while running prompt: {:#}", e);
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
            XSWDEvent::RequestApplication(app_state, callback) => {
                let prompt = prompt.clone();
                let res = xswd_handle_request_application(&prompt, app_state).await;
                if callback.send(res).is_err() {
                    error!("Error while sending application response back to XSWD");
                }
            },
            XSWDEvent::RequestPermission(app_state, request, callback) => {
                let res = xswd_handle_request_permission(&prompt, app_state, request).await;
                if callback.send(res).is_err() {
                    error!("Error while sending permission response back to XSWD");
                }
            },
            XSWDEvent::AppDisconnect(_) => {}
        };
    }
}

#[cfg(feature = "api_server")]
async fn xswd_handle_request_application(prompt: &ShareablePrompt, app_state: AppStateShared) -> Result<PermissionResult, Error> {
    let mut message = format!("XSWD: Application {} ({}) request access to your wallet", app_state.get_name(), app_state.get_id());
    let permissions = app_state.get_permissions().lock().await;
    if !permissions.is_empty() {
        message += &format!("\r\nPermissions ({}):", permissions.len());
        for perm in permissions.keys() {
            message += &format!("\r\n- {}", perm);
        }
    }

    message += "\r\n(Y/N): ";
    let accepted = prompt.read_valid_str_value(prompt.colorize_string(Color::Blue, &message), vec!["y", "n"]).await? == "y";
    if accepted {
        Ok(PermissionResult::Accept)
    } else {
        Ok(PermissionResult::Reject)
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
        "a" => PermissionResult::Accept,
        "d" => PermissionResult::Reject,
        "aa" => PermissionResult::AlwaysAccept,
        "ad" => PermissionResult::AlwaysReject,
        _ => unreachable!()
    })
}

// Apply the config passed in params
async fn apply_config(config: Config, wallet: &Arc<Wallet>, #[cfg(feature = "api_server")] prompt: &ShareablePrompt) {
    #[cfg(feature = "network_handler")]
    if !config.network_handler.offline_mode {
        info!("Trying to connect to daemon at '{}'", config.network_handler.daemon_address);
        if let Err(e) = wallet.set_online_mode(&config.network_handler.daemon_address, true).await {
            error!("Couldn't connect to daemon: {:#}", e);
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
                error!("Error while enabling RPC Server: {:#}", e);
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
    command_manager.remove_command("recover_seed")?;
    command_manager.remove_command("recover_private_key")?;
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
        "Show the balance of requested asset; Asset must be tracked",
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
        "transaction",
        "Show a specific transaction",
        vec![Arg::new("hash", ArgType::Hash)],
        CommandHandler::Async(async_handler!(transaction))
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
    command_manager.add_command(Command::with_required_arguments(
        "set_asset_name",
        "Set the name of an asset",
        vec![Arg::new("asset", ArgType::Hash)],
        CommandHandler::Async(async_handler!(set_asset_name))
    ))?;
    command_manager.add_command(Command::with_optional_arguments(
        "list_assets",
        "List all detected assets",
        vec![Arg::new("page", ArgType::Number)],
        CommandHandler::Async(async_handler!(list_assets))
    ))?;
    command_manager.add_command(Command::with_optional_arguments(
        "list_balances",
        "List all balances tracked",
        vec![Arg::new("page", ArgType::Number)],
        CommandHandler::Async(async_handler!(list_balances))
    ))?;
    command_manager.add_command(Command::with_optional_arguments(
        "list_tracked_assets",
        "List all assets marked as tracked",
        vec![Arg::new("page", ArgType::Number)],
        CommandHandler::Async(async_handler!(list_tracked_assets))
    ))?;
    command_manager.add_command(Command::with_optional_arguments(
        "track_asset",
        "Mark an asset hash as tracked",
        vec![Arg::new("asset", ArgType::Hash)],
        CommandHandler::Async(async_handler!(track_asset))
    ))?;
    command_manager.add_command(Command::with_optional_arguments(
        "untrack_asset",
        "Remove an asset hash from being tracked",
        vec![Arg::new("asset", ArgType::Hash)],
        CommandHandler::Async(async_handler!(untrack_asset))
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

    // Also add multisig commands
    command_manager.add_command(Command::with_optional_arguments(
        "multisig_setup",
        "Setup a multisig",
        vec![
            Arg::new("participants", ArgType::Number),
            Arg::new("threshold", ArgType::Number),
            Arg::new("confirm", ArgType::Bool)
        ],
        CommandHandler::Async(async_handler!(multisig_setup))
    ))?;
    command_manager.add_command(Command::with_optional_arguments(
        "multisig_sign",
        "Sign a multisig transaction",
        vec![
            Arg::new("tx_hash", ArgType::Hash)
        ],
        CommandHandler::Async(async_handler!(multisig_sign))
    ))?;
    command_manager.add_command(Command::new(
        "multisig_show",
        "Show the current state of multisig",
        CommandHandler::Async(async_handler!(multisig_show))
    ))?;

    command_manager.add_command(Command::new(
        "tx_version",
        "See the current transaction version",
        CommandHandler::Async(async_handler!(tx_version))
    ))?;
    command_manager.add_command(Command::new(
        "set_tx_version",
        "Set the transaction version",
        CommandHandler::Async(async_handler!(set_tx_version))
    ))?;
    command_manager.add_command(Command::new(
        "status",
        "See the status of the wallet",
        CommandHandler::Async(async_handler!(status))
    ))?;

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
                prompt.colorize_string(Color::Yellow, addr)
            };
    
            let storage = wallet.get_storage().read().await;
            let topoheight_str = format!(
                "{}: {}",
                prompt.colorize_string(Color::Yellow, "TopoHeight"),
                prompt.colorize_string(Color::Green, &format!("{}", storage.get_synced_topoheight().unwrap_or(0)))
            );
            let balance = format!(
                "{}: {}",
                prompt.colorize_string(Color::Yellow, "Balance"),
                prompt.colorize_string(Color::Green, &format_xelis(storage.get_plaintext_balance_for(&XELIS_ASSET).await.unwrap_or(0))),
            );
            let status = if wallet.is_online().await {
                prompt.colorize_string(Color::Green, "Online")
            } else {
                prompt.colorize_string(Color::Red, "Offline")
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
                    prompt.colorize_string(Color::Blue, "XELIS Wallet"),
                    addr_str,
                    topoheight_str,
                    balance,
                    status,
                    network_str,
                    prompt.colorize_string(Color::BrightBlack, ">>")
                )
            )
        }
    }

    Ok(
        format!(
            "{} {} ",
            prompt.colorize_string(Color::Blue, "XELIS Wallet"),
            prompt.colorize_string(Color::BrightBlack, ">>")
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
        Wallet::open(&dir, &password, *network, precomputed_tables, config.n_decryption_threads, config.network_concurrency)?
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

    if Path::new(&dir).is_dir() {
        manager.message("wallet already exists with this name");
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
        Wallet::create(&dir, &password, None, *network, precomputed_tables, config.n_decryption_threads, config.network_concurrency).await?
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
        Wallet::create(&dir, &password, Some(recover), *network, precomputed_tables, config.n_decryption_threads, config.network_concurrency).await?
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

// Set the asset name
async fn set_asset_name(manager: &CommandManager, mut args: ArgumentManager) -> Result<(), CommandError> {
    let prompt = manager.get_prompt();
    let context = manager.get_context().lock()?;
    let wallet: &Arc<Wallet> = context.get()?;

    let asset = args.get_value("asset")?.to_hash()?;
    let name = prompt.read_input("Asset name: ", false)
        .await.context("Error while reading asset name")?;

    let mut storage = wallet.get_storage().write().await;
    storage.set_asset_name(&asset, name).await?;
    manager.message("Asset name has been set");
    Ok(())
}

async fn list_assets(manager: &CommandManager, mut args: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let wallet: &Arc<Wallet> = context.get()?;

    let page = if args.has_argument("page") {
        args.get_value("page")?.to_number()? as usize
    } else {
        0
    };

    let storage = wallet.get_storage().read().await;
    let count = storage.get_assets_count()?;

    if count == 0 {
        manager.message("No assets found");
        return Ok(())
    }

    let mut max_pages = count / ELEMENTS_PER_PAGE;
    if count % ELEMENTS_PER_PAGE != 0 {
        max_pages += 1;
    }

    if page > max_pages {
        return Err(CommandError::InvalidArgument(format!("Page must be less than maximum pages ({})", max_pages - 1)));
    }

    manager.message(format!("Assets (page {}/{}):", page, max_pages));
    for res in storage.get_assets_with_data().await?.skip(page * ELEMENTS_PER_PAGE).take(ELEMENTS_PER_PAGE) {
        let (asset, data) = res?;
        manager.message(format!("{} ({} decimals): {}", asset, data.get_decimals(), data.get_name()));
    }

    Ok(())
}

async fn list_balances(manager: &CommandManager, mut args: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let wallet: &Arc<Wallet> = context.get()?;

    let page = if args.has_argument("page") {
        args.get_value("page")?.to_number()? as usize
    } else {
        0
    };

    let storage = wallet.get_storage().read().await;
    let count = storage.get_tracked_assets_count()?;

    if count == 0 {
        manager.message("No balances found");
        return Ok(())
    }

    let mut max_pages = count / ELEMENTS_PER_PAGE;
    if count % ELEMENTS_PER_PAGE != 0 {
        max_pages += 1;
    }

    if page > max_pages {
        return Err(CommandError::InvalidArgument(format!("Page must be less than maximum pages ({})", max_pages - 1)));
    }

    manager.message(format!("Balances (page {}/{}):", page, max_pages));
    for res in storage.get_tracked_assets()?.skip(page * ELEMENTS_PER_PAGE).take(ELEMENTS_PER_PAGE) {
        let asset = res?;
        if let Some(data) = storage.get_optional_asset(&asset).await? {
            let balance = storage.get_plaintext_balance_for(&asset).await?;
            manager.message(format!("Balance for asset {} ({}): {}", data.get_name(), asset, format_coin(balance, data.get_decimals())));
        } else {
            manager.message(format!("No asset data for {}", asset));
        }

    }

    Ok(())
}

async fn list_tracked_assets(manager: &CommandManager, mut args: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let wallet: &Arc<Wallet> = context.get()?;

    let page = if args.has_argument("page") {
        args.get_value("page")?.to_number()? as usize
    } else {
        0
    };

    let storage = wallet.get_storage().read().await;

    let count = storage.get_tracked_assets_count()?;
    if count == 0 {
        manager.message("No tracked assets found");
        return Ok(())
    }

    let mut max_pages = count / ELEMENTS_PER_PAGE;
    if count % ELEMENTS_PER_PAGE != 0 {
        max_pages += 1;
    }

    if page > max_pages {
        return Err(CommandError::InvalidArgument(format!("Page must be less than maximum pages ({})", max_pages - 1)));
    }

    manager.message(format!("Assets (page {}/{}):", page, max_pages));
    for res in storage.get_tracked_assets()?.skip(page * ELEMENTS_PER_PAGE).take(ELEMENTS_PER_PAGE) {
        let asset = res?;
        if let Some(data) = storage.get_optional_asset(&asset).await? {
            manager.message(format!("{} ({} decimals): {}", asset, data.get_decimals(), data.get_name()));
        } else {
            manager.message(format!("No asset data for {}", asset));
        }
    }

    Ok(())
}

async fn track_asset(manager: &CommandManager, mut args: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let wallet: &Arc<Wallet> = context.get()?;
    let prompt = manager.get_prompt();

    let asset = if args.has_argument("asset") {
        args.get_value("asset")?.to_hash()?
    } else {
        prompt.read_hash(prompt.colorize_string(Color::BrightGreen, "Asset ID: ")).await?
    };

    if wallet.track_asset(asset).await.context("Error while tracking asset")? {
        manager.message("Asset ID is already tracked!");
    } else {
        manager.message("Asset ID is now tracked");
    }

    Ok(())
}

async fn untrack_asset(manager: &CommandManager, mut args: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let wallet: &Arc<Wallet> = context.get()?;
    let prompt = manager.get_prompt();

    let asset = if args.has_argument("asset") {
        args.get_value("asset")?.to_hash()?
    } else {
        prompt.read_hash(prompt.colorize_string(Color::BrightGreen, "Asset ID: ")).await?
    };

    if asset == XELIS_ASSET {
        manager.message("XELIS asset cannot be untracked");
    } else if wallet.untrack_asset(asset).await.context("Error while untracking asset")? {
        manager.message("Asset ID is not marked as tracked!");
    } else {
        manager.message("Asset ID is not tracked anymore");
    }

    Ok(())
}

// Change wallet password
async fn change_password(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let wallet: &Arc<Wallet> = context.get()?;

    let prompt = manager.get_prompt();

    let old_password = prompt.read_input(prompt.colorize_string(Color::BrightRed, "Current Password: "), true)
        .await
        .context("Error while asking old password")?;

    let new_password = prompt.read_input(prompt.colorize_string(Color::BrightRed, "New Password: "), true)
        .await
        .context("Error while asking new password")?;

    manager.message("Changing password...");
    wallet.set_password(&old_password, &new_password).await?;
    manager.message("Your password has been changed!");
    Ok(())
}

async fn create_transaction_with_multisig(manager: &CommandManager, prompt: &Prompt, wallet: &Wallet, tx_type: TransactionTypeBuilder, payload: MultiSigPayload) -> Result<Transaction, CommandError> {
    manager.message(format!("Multisig detected, you need to sign the transaction with {} keys.", payload.threshold));

    let mut storage = wallet.get_storage().write().await;
    let fee = FeeBuilder::default();
    let mut state = wallet.create_transaction_state_with_storage(&storage, &tx_type, &fee, None).await
        .context("Error while creating transaction state")?;

    let mut unsigned = wallet.create_unsigned_transaction(&mut state, Some(payload.threshold), tx_type, fee, storage.get_tx_version().await?)
        .context("Error while building unsigned transaction")?;

    let mut multisig = MultiSig::new();
    manager.message(format!("Transaction hash to sign: {}", unsigned.get_hash_for_multisig()));

    if payload.threshold == 1 {
        let signature = prompt.read_input("Enter signature hexadecimal: ", false).await
            .context("Error while reading signature")?;
        let signature = Signature::from_hex(&signature).context("Invalid signature")?;

        let id = if payload.participants.len() == 1 {
            0
        } else {
            prompt.read("Enter signer ID: ").await
            .context("Error while reading signer id")?
        };

        if !multisig.add_signature(SignatureId {
            id,
            signature
        }) {
            return Err(CommandError::InvalidArgument("Invalid signature".to_string()));
        }        
    } else {
        manager.message("Participants available:");
        for (i, participant) in payload.participants.iter().enumerate() {
            manager.message(format!("Participant #{}: {}", i, participant.as_address(wallet.get_network().is_mainnet())));
        }
        
        manager.message("Please enter the signatures and signer IDs");
        for i in 0..payload.threshold {
            let signature = prompt.read_input(format!("Enter signature #{} hexadecimal: ", i), false).await
                .context("Error while reading signature")?;
            let signature = Signature::from_hex(&signature).context("Invalid signature")?;
    
            let id = prompt.read("Enter signer ID for signature: ").await
                .context("Error while reading signer id")?;
    
            if !multisig.add_signature(SignatureId {
                id,
                signature
            }) {
                return Err(CommandError::InvalidArgument("Invalid signature".to_string()));
            }
        }
    }

    unsigned.set_multisig(multisig);

    let tx = unsigned.finalize(wallet.get_keypair());
    state.set_tx_hash_built(tx.hash());

    state.apply_changes(&mut storage).await.context("Error while applying changes")?;

    Ok(tx)
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
            prompt.colorize_string(Color::Green, "Address: "),
            false
        ).await.context("Error while reading address")?
    };
    let address = Address::from_string(&str_address).context("Invalid address")?;

    let asset = if args.has_argument("asset") {
        args.get_value("asset")?.to_hash()?
    } else {
        let asset_name = prompt.read_input(
            prompt.colorize_string(Color::Green, "Asset (default XELIS): "),
            false
        ).await?;
        if asset_name.is_empty() {
            XELIS_ASSET
        } else if asset_name.len() == HASH_SIZE * 2 {
            Hash::from_hex(&asset_name).context("Error while reading hash from hex")?
        } else {
            let storage = wallet.get_storage().read().await;
            storage.get_asset_by_name(&asset_name).await?
                .context("No asset registered with given name")?
        }
    };

    let (max_balance, asset_data, multisig) = {
        let storage = wallet.get_storage().read().await;
        let balance = storage.get_plaintext_balance_for(&asset).await.unwrap_or(0);
        let asset = storage.get_asset(&asset).await?;
        let multisig = storage.get_multisig_state().await.context("Error while reading multisig state")?;
        (balance, asset, multisig.cloned())
    };

    // read amount
    let amount = if args.has_argument("amount") {
        args.get_value("amount")?.to_string_value()?
    } else {
        prompt.read(
            prompt.colorize_string(Color::Green, &format!("Amount (max: {}): ", format_coin(max_balance, asset_data.get_decimals())))
        ).await.context("Error while reading amount")?
    };

    let amount = from_coin(amount, asset_data.get_decimals()).context("Invalid amount")?;
    manager.message(format!("Sending {} of {} ({}) to {}", format_coin(amount, asset_data.get_decimals()), asset_data.get_name(), asset, address.to_string()));

    if !args.get_flag("confirm")? && !prompt.ask_confirmation().await.context("Error while confirming action")? {
        manager.message("Transaction has been aborted");
        return Ok(())
    }

    manager.message("Building transaction...");
    let transfer = TransferBuilder {
        destination: address,
        amount,
        asset,
        extra_data: None,
        encrypt_extra_data: true
    };
    let tx_type = TransactionTypeBuilder::Transfers(vec![transfer]);
    let tx = if let Some(multisig) = multisig {
        create_transaction_with_multisig(manager, prompt, wallet, tx_type, multisig.payload).await?
    } else {
        match wallet.create_transaction(tx_type, FeeBuilder::default()).await {
            Ok(tx) => tx,
            Err(e) => {
                manager.error(&format!("Error while creating transaction: {}", e));
                return Ok(())
            }
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
            prompt.colorize_string(Color::Green, "Address: "),
            false
        ).await.context("Error while reading address")?
    };
    let address = Address::from_string(&str_address).context("Invalid address")?;

    let mut asset = args.get_value("asset").and_then(|v| v.to_hash()).ok();
    if asset.is_none() {
        asset = prompt.read_hash(
           prompt.colorize_string(Color::Green, "Asset (default XELIS): ")
       ).await.ok();
    }

    let asset = asset.unwrap_or(XELIS_ASSET);
    let (mut amount, asset_data, multisig) = {
        let storage = wallet.get_storage().read().await;
        let amount = storage.get_plaintext_balance_for(&asset).await.unwrap_or(0);
        let data = storage.get_asset(&asset).await?;
        let multisig = storage.get_multisig_state().await
            .context("Error while reading multisig state")?;
        (amount, data, multisig.cloned())
    };

    let transfer = TransferBuilder {
        destination: address.clone(),
        amount,
        asset: asset.clone(),
        extra_data: None,
        encrypt_extra_data: true
    };
    let tx_type = TransactionTypeBuilder::Transfers(vec![transfer]);
    let estimated_fees = wallet.estimate_fees(tx_type.clone(), FeeBuilder::default()).await.context("Error while estimating fees")?;

    if asset == XELIS_ASSET {
        amount = amount.checked_sub(estimated_fees).context("Insufficient balance to pay fees")?;
    }

    manager.message(format!("Sending {} of {} ({}) to {} (fees: {})", format_coin(amount, asset_data.get_decimals()), asset_data.get_name(), asset, address, format_xelis(estimated_fees)));

    if !args.get_flag("confirm")? && !prompt.ask_confirmation().await.context("Error while confirming action")? {
        manager.message("Transaction has been aborted");
        return Ok(())
    }

    manager.message("Building transaction...");
    let transfer = TransferBuilder {
        destination: address,
        amount,
        asset,
        extra_data: None,
        encrypt_extra_data: true
    };
    let tx_type = TransactionTypeBuilder::Transfers(vec![transfer]);
    let tx = if let Some(multisig) = multisig {
        create_transaction_with_multisig(manager, prompt, wallet, tx_type, multisig.payload).await?
    } else {
        match wallet.create_transaction(tx_type, FeeBuilder::default()).await {
            Ok(tx) => tx,
            Err(e) => {
                manager.error(&format!("Error while creating transaction: {}", e));
                return Ok(())
            }
        }
    };

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
            prompt.colorize_string(Color::Green, "Asset (default XELIS): ")
        ).await.unwrap_or(XELIS_ASSET)
    };

    let (max_balance, asset_data, multisig) = {
        let storage = wallet.get_storage().read().await;
        let balance = storage.get_plaintext_balance_for(&asset).await.unwrap_or(0);
        let data = storage.get_asset(&asset).await?;
        let multisig = storage.get_multisig_state().await
            .context("Error while reading multisig state")?;
        (balance, data, multisig.cloned())
    };

    // read amount
    let amount = if args.has_argument("amount") {
        args.get_value("amount")?.to_string_value()?
    } else {
        prompt.read(
            prompt.colorize_string(Color::Green, &format!("Amount (max: {}): ", format_coin(max_balance, asset_data.get_decimals())))
        ).await.context("Error while reading amount")?
    };

    let amount = from_coin(amount, asset_data.get_decimals()).context("Invalid amount")?;
    manager.message(format!("Burning {} of {} ({})", format_coin(amount, asset_data.get_decimals()), asset_data.get_name(), asset));
    if !args.get_flag("confirm")? && !prompt.ask_confirmation().await.context("Error while confirming action")? {
        manager.message("Transaction has been aborted");
        return Ok(())
    }

    manager.message("Building transaction...");
    let payload = BurnPayload {
        amount,
        asset
    };

    let tx_type = TransactionTypeBuilder::Burn(payload);
    let tx = if let Some(multisig) = multisig {
        create_transaction_with_multisig(manager, prompt, wallet, tx_type, multisig.payload).await?
    } else {
        match wallet.create_transaction(tx_type, FeeBuilder::default()).await {
            Ok(tx) => tx,
            Err(e) => {
                manager.error(&format!("Error while creating transaction: {}", e));
                return Ok(())
            }
        }
    };

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
    let prompt = manager.get_prompt();
    let wallet: &Arc<Wallet> = context.get()?;
    let storage = wallet.get_storage().read().await;

    let asset = if arguments.has_argument("asset") {
        arguments.get_value("asset")?.to_hash()?
    } else {
        prompt.read_hash(
            prompt.colorize_string(Color::Green, "Asset (default XELIS): ")
        ).await.unwrap_or(XELIS_ASSET)
    };
    let balance = storage.get_plaintext_balance_for(&asset).await?;
    let data = storage.get_asset(&asset).await?;
    manager.message(format!("Balance for asset {} ({}): {}", data.get_name(), asset, format_coin(balance, data.get_decimals())));
    Ok(())
}

// Show all transactions
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

    let txs_len = storage.get_transactions_count()?;
    // if we don't have any txs, no need proceed further
    if txs_len == 0 {
        manager.message("No transactions available");
        return Ok(())
    }

    let mut max_pages = txs_len / ELEMENTS_PER_PAGE;
    if txs_len % ELEMENTS_PER_PAGE != 0 {
        max_pages += 1;
    }

    if page > max_pages {
        return Err(CommandError::InvalidArgument(format!("Page must be less than maximum pages ({})", max_pages)));
    }

    let transactions = storage.get_filtered_transactions(
        None,
        None,
        None,
        None,
        true,
        true,
        true,
        true,
        None,
        Some(ELEMENTS_PER_PAGE),
        Some((page - 1) * ELEMENTS_PER_PAGE)
    )?;

    manager.message(format!("{} Transactions (total {}) page {}/{}:", transactions.len(), txs_len, page, max_pages));
    for tx in transactions {
        manager.message(format!("- {}", tx.summary(wallet.get_network().is_mainnet(), &*storage).await?));
    }

    Ok(())
}

async fn transaction(manager: &CommandManager, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let wallet: &Arc<Wallet> = context.get()?;
    let storage = wallet.get_storage().read().await;
    let hash = arguments.get_value("hash")?.to_hash()?;
    let tx = storage.get_transaction(&hash).context("Transaction not found")?;
    manager.message(tx.summary(wallet.get_network().is_mainnet(), &*storage).await?);
    Ok(())
}

async fn export_transactions_csv(manager: &CommandManager, mut arguments: ArgumentManager) -> Result<(), CommandError> {
    let filename = arguments.get_value("filename")?.to_string_value()?;
    let context = manager.get_context().lock()?;
    let wallet: &Arc<Wallet> = context.get()?;
    let storage = wallet.get_storage().read().await;
    let transactions = storage.get_transactions()?;
    let mut file = File::create(&filename).context("Error while creating CSV file")?;

    wallet.export_transactions_in_csv(&storage, transactions, &mut file).await.context("Error while exporting transactions to CSV")?;

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
        manager.error(format!("Error while rescanning: {:#}", e));
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
    let unconfirmed_nonce = storage.get_unconfirmed_nonce()?;
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

async fn tx_version(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let wallet: &Arc<Wallet> = context.get()?;
    let storage = wallet.get_storage().read().await;
    let version = storage.get_tx_version().await?;
    manager.message(format!("Transaction version: {}", version));
    Ok(())
}

async fn set_tx_version(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    let value: u8 = manager.get_prompt().read("New Transaction Version: ".to_string()).await
        .context("Error while reading new transaction version to set")?;

    let tx_version = TxVersion::try_from(value)
        .map_err(|_| CommandError::InvalidArgument("Invalid transaction version".to_string()))?;

    let context = manager.get_context().lock()?;
    let wallet: &Arc<Wallet> = context.get()?;
    let mut storage = wallet.get_storage().write().await;
    storage.set_tx_version(tx_version).await?;

    manager.message(format!("New transaction version is: {}", value));
    Ok(())
}

async fn status(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let wallet: &Arc<Wallet> = context.get()?;

    if let Some(network_handler) = wallet.get_network_handler().lock().await.as_ref() {
        let api = network_handler.get_api();
        let is_online = api.get_client().is_online();
        manager.message(format!("Network handler is online: {}", is_online));
        manager.message(format!("Connected to: {}", api.get_client().get_target()));

        if is_online {
            let info = api.get_info().await
                .context("Error while getting network info")?;

            manager.message("--- Daemon status ---");
            manager.message(format!("Height: {}", info.height));
            manager.message(format!("Topoheight: {}", info.topoheight));
            manager.message(format!("Stable height: {}", info.stableheight));
            manager.message(format!("Pruned topoheight: {:?}", info.pruned_topoheight));
            manager.message(format!("Top block hash: {}", info.top_block_hash));
            manager.message(format!("Network: {}", info.network));
            manager.message(format!("Emitted supply: {}", format_xelis(info.emitted_supply)));
            manager.message(format!("Burned supply: {}", format_xelis(info.burned_supply)));
            manager.message(format!("Circulating supply: {}", format_xelis(info.circulating_supply)));
            manager.message("---------------------");
        }
    }

    let storage = wallet.get_storage().read().await;
    let multisig = storage.get_multisig_state().await?;
    if let Some(multisig) = multisig {
        manager.message("--- Multisig: ---");
        manager.message(format!("Threshold: {}", multisig.payload.threshold));
        manager.message(format!("Participants ({}): {}", multisig.payload.participants.len(),
            multisig.payload.participants.iter()
                .map(|p| p.as_address(wallet.get_network().is_mainnet()).to_string())
                .collect::<Vec<_>>().join(", ")
            ));
        manager.message("---------------");
    } else {
        manager.message("No multisig state");
    }

    let tx_version = storage.get_tx_version().await?;
    manager.message(format!("Transaction version: {}", tx_version));
    let nonce = storage.get_nonce()?;
    let unconfirmed_nonce = storage.get_unconfirmed_nonce()?;
    manager.message(format!("Nonce: {}", nonce));
    if nonce != unconfirmed_nonce {
        manager.message(format!("Unconfirmed nonce: {}", unconfirmed_nonce));
    }
    let network = wallet.get_network();
    manager.message(format!("Synced topoheight: {}", storage.get_synced_topoheight()?));
    manager.message(format!("Network: {}", network));
    manager.message(format!("Wallet address: {}", wallet.get_address()));

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

// Setup a multisig transaction (a multisig is present on chain, but this wallet is offline so can't sync it)
async fn multisig_setup(manager: &CommandManager, mut args: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let wallet: &Arc<Wallet> = context.get()?;
    let prompt = manager.get_prompt();

    let multisig = {
        let storage = wallet.get_storage().read().await;
        storage.get_multisig_state().await?.cloned()
    };

    manager.warn("IMPORTANT: Make sure you have the correct participants and threshold before proceeding.");
    manager.warn("If you are unsure, please cancel and verify the participants and threshold.");
    manager.warn("An incorrect setup can lead to loss of funds.");
    manager.warn("Do you want to continue?");

    if !prompt.ask_confirmation().await.context("Error while confirming action")? {
        manager.message("Transaction has been aborted");
        return Ok(())
    }

    let participants: u8 = if args.has_argument("participants") {
        args.get_value("participants")?.to_number()? as u8
    } else {
        let msg = if multisig.is_some() {
            "Participants count (0 to delete): "
        } else {
            "Participants count (min. 1): "
        };
        prompt.read(msg)
            .await.context("Error while reading participants count")?
    };

    if participants == 0 {
        let Some(multisig) = multisig else {
            return Err(CommandError::InvalidArgument("Participants count must be greater than 0".to_string()));
        };

        manager.warn("Participants count is 0, this will delete the multisig currently configured");
        manager.warn("Do you want to continue?");
        if !args.get_flag("confirm")? && !prompt.ask_confirmation().await.context("Error while confirming action")? {
            manager.message("Transaction has been aborted");
            return Ok(())
        }

        let payload = MultiSigBuilder {
            participants: IndexSet::new(),
            threshold: 0
        };

        let tx = create_transaction_with_multisig(manager, prompt, wallet, TransactionTypeBuilder::MultiSig(payload), multisig.payload).await?;

        broadcast_tx(wallet, manager, tx).await;
        return Ok(())
    }

    let threshold: u8 = if args.has_argument("threshold") {
        args.get_value("threshold")?.to_number()? as u8
    } else {
        prompt.read("Threshold (min. 1): ")
            .await.context("Error while reading threshold")?
    };

    if threshold == 0 {
        return Err(CommandError::InvalidArgument("Threshold must be greater than 0".to_string()));
    }

    if threshold > participants {
        return Err(CommandError::InvalidArgument("Threshold must be less or equal to participants count".to_string()));
    }

    let mainnet = wallet.get_network().is_mainnet();
    let mut keys = IndexSet::with_capacity(participants as usize);
    for i in 0..participants {
        let address: Address = prompt.read(format!("Participant #{} address: ", i + 1))
            .await.context("Error while reading participant address")?;

        if address.is_mainnet() != mainnet {
            return Err(CommandError::InvalidArgument("Participant address must be on the same network".to_string()));
        }

        if !address.is_normal() {
            return Err(CommandError::InvalidArgument("Participant address must be a normal address".to_string()));
        }

        if address.get_public_key() == wallet.get_public_key() {
            return Err(CommandError::InvalidArgument("Participant address cannot be the same as the wallet address".to_string()));
        }

        if !keys.insert(address) {
            return Err(CommandError::InvalidArgument("Participant address already exists".to_string()));
        }
    }

    manager.message(format!("MultiSig payload ({} participants with threshold at {}):", participants, threshold));
    for key in keys.iter() {
        manager.message(format!("- {}", key));
    }

    if !args.get_flag("confirm")? && !prompt.ask_confirmation().await.context("Error while confirming action")? {
        manager.message("Transaction has been aborted");
        return Ok(())
    }

    manager.message("Building transaction...");

    let multisig = {
        let storage = wallet.get_storage().read().await;
        storage.get_multisig_state().await.context("Error while reading multisig state")?
            .cloned()
    };
    let payload = MultiSigBuilder {
        participants: keys,
        threshold
    };
    let tx_type = TransactionTypeBuilder::MultiSig(payload);
    let tx = if let Some(multisig) = multisig {
        create_transaction_with_multisig(manager, prompt, wallet, tx_type, multisig.payload).await?
    } else {
        match wallet.create_transaction(tx_type, FeeBuilder::default()).await {
            Ok(tx) => tx,
            Err(e) => {
                manager.error(&format!("Error while creating transaction: {}", e));
                return Ok(())
            }
        }
    };

    broadcast_tx(wallet, manager, tx).await;

    Ok(())
}

async fn multisig_sign(manager: &CommandManager, mut args: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let wallet: &Arc<Wallet> = context.get()?;
    let prompt = manager.get_prompt();

    let tx_hash = if args.has_argument("tx_hash") {
        args.get_value("tx_hash")?.to_hash()?
    } else {
        prompt.read("Transaction hash: ").await.context("Error while reading transaction hash")?
    };

    let signature = wallet.sign_data(tx_hash.as_bytes());
    prompt.read_input(format!("Signature: {}\r\nPress ENTER to continue", signature.to_hex()), false).await
        .context("Error while displaying seed")?;

    Ok(())
}

async fn multisig_show(manager: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    let context = manager.get_context().lock()?;
    let wallet: &Arc<Wallet> = context.get()?;
    let storage = wallet.get_storage().read().await;
    let multisig = storage.get_multisig_state().await.context("Error while reading multisig state")?;

    if let Some(multisig) = multisig {
        manager.message(format!("MultiSig payload ({} participants with threshold at {}):", multisig.payload.participants.len(), multisig.payload.threshold));
        for key in multisig.payload.participants.iter() {
            manager.message(format!("- {}", key.as_address(wallet.get_network().is_mainnet())));
        }
    } else {
        manager.message("No multisig configured");
    }

    Ok(())
}

// broadcast tx if possible
// submit_transaction increase the local nonce in storage in case of success
async fn broadcast_tx(wallet: &Wallet, manager: &CommandManager, tx: Transaction) {
    let tx_hash = tx.hash();
    manager.message(format!("Transaction hash: {}", tx_hash));

    if wallet.is_online().await {
        if let Err(e) = wallet.submit_transaction(&tx).await {
            manager.error(format!("Couldn't submit transaction: {:#}", e));
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