use std::ops::ControlFlow;

use log::info;
use serde::{Deserialize, Serialize};
use xelis_common::{
    config::VERSION,
    crypto::ecdlp,
    network::Network,
    utils::detect_available_parallelism
};
#[cfg(feature = "cli")]
use {
    clap::Parser,
    xelis_common::prompt::{
        default_logs_datetime_format,
        LogLevel,
        ModuleConfig
    }
};
use crate::{
    precomputed_tables,
    wallet::HistoryScanMode
};

pub const DIR_PATH: &str = "wallets/";
pub const XSWD_BIND_ADDRESS: &str = "127.0.0.1:44325";
pub const PASSWORD_HASH_SIZE: usize = 32;
pub const SALT_SIZE: usize = 32;
pub const KEY_SIZE: usize = 32;

// Default daemon address when none is provided.
pub const DEFAULT_DAEMON_ADDRESS: &str = "http://127.0.0.1:8080";
// Auto-reconnect interval in seconds for the network handler.
pub const AUTO_RECONNECT_INTERVAL: u64 = 5;

/// RPC server options used when the wallet exposes its API over HTTP.
#[cfg(all(feature = "api_server", feature = "cli"))]
#[derive(Debug, clap::Args, Serialize, Deserialize)]
pub struct RPCConfig {
    /// Address the RPC server listens on.
    #[clap(long)]
    pub rpc_bind_address: Option<String>,
    /// Username required for RPC authentication.
    #[clap(long)]
    pub rpc_username: Option<String>,
    /// Password required for RPC authentication.
    #[clap(long)]
    pub rpc_password: Option<String>,
    /// Number of worker threads used by the RPC server.
    #[clap(long)]
    pub rpc_threads: Option<usize>
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

#[cfg(feature = "cli")]
#[derive(Debug, clap::Args, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Daemon RPC endpoint used to sync the wallet.
    #[cfg(feature = "network_handler")]
    #[clap(long, default_value_t = String::from(DEFAULT_DAEMON_ADDRESS))]
    #[serde(default = "default_daemon_address")]
    pub daemon_address: String,
    /// Start without connecting to a daemon.
    #[cfg(feature = "network_handler")]
    #[clap(long)]
    pub offline_mode: bool,
}

#[cfg(feature = "cli")]
#[derive(Debug, clap::Args, Serialize, Deserialize)]
pub struct PrecomputedTablesConfig {
    /// L1 size used for precomputed tables.
    ///
    /// The default is `26`, which uses about 330 MB.
    /// At each increment of 1, the size of the table is doubled.
    #[clap(long, default_value_t = precomputed_tables::L1_FULL)]
    #[serde(default = "default_precomputed_tables_l1")]
    pub precomputed_tables_l1: usize,
    /// Directory used to read or generate precomputed tables.
    ///
    /// Defaults to the current directory.
    #[clap(long)]
    pub precomputed_tables_path: Option<String>,
}

#[cfg(feature = "cli")]
#[derive(Debug, clap::Args, Serialize, Deserialize)]
pub struct LogConfig {
    /// Minimum log level printed to the terminal.
    #[clap(long, value_enum, default_value_t)]
    #[serde(default)]
    pub log_level: LogLevel,
    /// Minimum log level written to the log file.
    ///
    /// Defaults to the terminal log level.
    #[clap(long, value_enum)]
    pub file_log_level: Option<LogLevel>,
    /// Disable writing logs to a file.
    #[clap(long)]
    #[serde(default)]
    pub disable_file_logging: bool,
    /// Disable date-based log filenames.
    ///
    /// When enabled, the log file is named `xelis-wallet.log` instead of
    /// `YYYY-MM-DD.xelis-wallet.log`.
    #[clap(long)]
    #[serde(default)]
    pub disable_file_log_date_based: bool,
    /// Compress rotated log files automatically.
    ///
    /// This only applies when file logging is enabled.
    #[clap(long)]
    #[serde(default)]
    pub auto_compress_logs: bool,
    /// Disable colors in terminal logs.
    #[clap(long)]
    #[serde(default)]
    pub disable_log_color: bool,
    /// Disable the interactive terminal prompt.
    ///
    /// CLI commands and live prompt updates are unavailable in this mode.
    #[clap(long)]
    #[serde(default)]
    pub disable_interactive_mode: bool,
    /// Log filename stored inside `logs_path`.
    ///
    /// Defaults to `xelis-wallet.log`. Unless date-based filenames are disabled,
    /// daily log files are named `YYYY-MM-DD.xelis-wallet.log`.
    #[clap(long, default_value_t = default_log_filename())]
    #[serde(default = "default_log_filename")]
    pub filename_log: String,
    /// Directory where log files are written.
    ///
    /// Defaults to `logs/`. The path must end with `/` or `\`.
    #[clap(long, default_value_t = default_logs_path())]
    #[serde(default = "default_logs_path")]
    pub logs_path: String,
    /// Per-module log filters.
    #[clap(long)]
    #[serde(default)]
    pub logs_modules: Vec<ModuleConfig>,
    /// Disable the ASCII art shown at startup.
    #[clap(long)]
    #[serde(default)]
    pub disable_ascii_art: bool,
    /// Datetime format used in log entries.
    #[clap(long, default_value_t = default_logs_datetime_format())]
    #[serde(default = "default_logs_datetime_format")]
    pub datetime_format: String,
}

#[cfg(feature = "cli")]
#[derive(Parser, Serialize, Deserialize)]
#[clap(version = VERSION, about = "Command-line wallet for XELIS. Create, open, recover, sync, and manage encrypted wallets, balances, and transactions.")]
#[command(styles = xelis_common::get_cli_styles())]
pub struct Config {
    /// RPC server configuration.
    #[cfg(feature = "api_server")]
    #[structopt(flatten)]
    pub rpc: RPCConfig,
    /// Network connection configuration.
    #[structopt(flatten)]
    pub network_handler: NetworkConfig,
    /// Precomputed table configuration.
    #[structopt(flatten)]
    pub precomputed_tables: PrecomputedTablesConfig,
    /// Log output configuration.
    #[structopt(flatten)]
    pub log: LogConfig,
    /// Wallet directory to open or create.
    #[clap(long)]
    pub wallet_path: Option<String>,
    /// Password used to open the wallet.
    #[clap(long)]
    pub password: Option<String>,
    /// Recover the wallet from a seed phrase.
    #[clap(long)]
    pub seed: Option<String>,
    /// Number of threads used for ciphertext decryption.
    #[clap(long, default_value_t = detect_available_parallelism())]
    #[serde(default = "detect_available_parallelism")]
    pub n_decryption_threads: usize,
    /// Maximum number of concurrent network handler tasks.
    #[clap(long, default_value_t = detect_available_parallelism())]
    #[serde(default = "detect_available_parallelism")]
    pub network_concurrency: usize,
    /// Network to use for addresses, sync, and transactions.
    #[clap(long, value_enum, default_value_t = Network::Mainnet)]
    #[serde(default)]
    pub network: Network,
    /// Enable the XSWD server.
    #[cfg(feature = "api_server")]
    #[clap(long)]
    #[serde(default)]
    pub enable_xswd: bool,
    /// History scan mode used during wallet synchronization.
    ///
    /// Modes that skip history only store blocks and transactions received after
    /// the wallet starts.
    #[clap(long, default_value_t = HistoryScanMode::default())]
    #[serde(default)]
    pub history_scan_mode: HistoryScanMode,
    /// Use only stable balance when building transactions.
    ///
    /// This avoids spending funds that may be affected by a DAG reorg and only
    /// applies while the wallet is online.
    #[clap(long)]
    #[serde(default)]
    pub force_stable_balance: bool,
    /// JSON configuration file to load.
    #[clap(long)]
    #[serde(skip)]
    #[serde(default)]
    pub config_file: Option<String>,
    /// Generate a configuration template at `config_file`.
    #[clap(long)]
    #[serde(skip)]
    #[serde(default)]
    pub generate_config_template: bool
}

/// Logs precomputed table generation progress.
pub struct LogProgressTableGenerationReportFunction;

impl ecdlp::ProgressTableGenerationReportFunction for LogProgressTableGenerationReportFunction {
    fn report(&self, progress: f64, step: ecdlp::ReportStep) -> ControlFlow<()> {
        info!("Progress: {:.2}% on step {:?}", progress * 100.0, step);
        ControlFlow::Continue(())
    }
}