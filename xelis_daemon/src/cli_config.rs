use serde::{Deserialize, Serialize};
use xelis_common::{
    config::VERSION,
    network::Network,
    prompt::{
        default_logs_datetime_format,
        LogLevel,
        ModuleConfig
    }
};

use crate::core::config::{BlockchainConfig as InnerConfig, StorageBackend};

#[cfg(feature = "rocksdb")]
use crate::core::storage::RocksDBConfig;

#[cfg(feature = "sled")]
use crate::core::storage::SledConfig;

fn default_filename_log() -> String {
    "xelis-daemon.log".to_owned()
}

fn default_logs_path() -> String {
    "logs/".to_owned()
}

#[derive(Debug, Clone, clap::Parser, Serialize, Deserialize)]
pub struct LogConfig {
    /// Minimum log level printed to the terminal.
    #[clap(long, value_enum, default_value_t = LogLevel::Info)]
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
    /// When enabled, the log file is named `xelis-daemon.log` instead of
    /// `YYYY-MM-DD.xelis-daemon.log`.
    #[clap(long)]
    #[serde(default)]
    pub disable_file_log_date_based: bool,
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
    /// Compress rotated log files automatically.
    ///
    /// This only applies when file logging is enabled.
    #[clap(long)]
    #[serde(default)]
    pub auto_compress_logs: bool,
    /// Log filename stored inside `logs_path`.
    ///
    /// Unless date-based filenames are disabled, daily log files are named `YYYY-MM-DD.xelis-daemon.log`.
    #[clap(long, default_value_t = default_filename_log())]
    #[serde(default = "default_filename_log")]
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

#[derive(clap::Parser, Serialize, Deserialize)]
#[clap(version = VERSION, about = "XELIS daemon node. Synchronizes and validates the blockchain, participates in the P2P network, and serves RPC and mining work.")]
#[command(styles = xelis_common::get_cli_styles())]
pub struct CliConfig {
    /// Core blockchain, P2P, RPC, mempool, and simulator settings.
    #[structopt(flatten)]
    pub core: InnerConfig,
    /// Sled storage backend settings.
    #[cfg(feature = "sled")]
    #[clap(flatten)]
    #[serde(default)]
    pub sled: SledConfig,
    /// RocksDB storage backend settings.
    #[cfg(feature = "rocksdb")]
    #[clap(flatten)]
    #[serde(default)]
    pub rocksdb: RocksDBConfig,
    /// Storage backend used by the daemon.
    ///
    /// Existing data is not migrated when switching backends. Select the backend
    /// that matches the data directory you intend to use.
    #[clap(long, value_enum, default_value_t)]
    #[serde(default)]
    pub use_db_backend: StorageBackend,
    /// Log output configuration.
    #[structopt(flatten)]
    pub log: LogConfig,
    /// Network to run and validate.
    #[clap(long, value_enum, default_value_t = Network::Mainnet)]
    #[serde(default)]
    pub network: Network,
    /// JSON configuration file to load.
    #[clap(long)]
    #[serde(skip)]
    #[serde(default)]
    pub config_file: Option<String>,
    /// Generate a configuration template at `config_file`.
    #[clap(long)]
    #[serde(skip)]
    #[serde(default)]
    pub generate_config_template: bool,
}
