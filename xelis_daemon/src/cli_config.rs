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
    /// Set log level
    #[clap(long, value_enum, default_value_t = LogLevel::Info)]
    #[serde(default)]
    pub log_level: LogLevel,
    /// Set file log level
    /// By default, it will be the same as log level
    #[clap(long, value_enum)]
    pub file_log_level: Option<LogLevel>,
    /// Disable the log file
    #[clap(long)]
    #[serde(default)]
    pub disable_file_logging: bool,
    /// Disable the log filename date based
    /// If disabled, the log file will be named xelis-daemon.log instead of YYYY-MM-DD.xelis-daemon.log
    #[clap(long)]
    #[serde(default)]
    pub disable_file_log_date_based: bool,
    /// Disable the usage of colors in log
    #[clap(long)]
    #[serde(default)]
    pub disable_log_color: bool,
    /// Disable terminal interactive mode
    /// You will not be able to write CLI commands in it or to have an updated prompt
    #[clap(long)]
    #[serde(default)]
    pub disable_interactive_mode: bool,
    /// Enable the log file auto compression
    /// If enabled, the log file will be compressed every day
    /// This will only work if the log file is enabled
    #[clap(long)]
    #[serde(default)]
    pub auto_compress_logs: bool,
    /// Log filename
    ///
    /// By default filename is xelis-daemon.log.
    /// File will be stored in logs directory, this is only the filename, not the full path.
    /// Log file is rotated every day and has the format YYYY-MM-DD.xelis-daemon.log.
    #[clap(long, default_value_t = default_filename_log())]
    #[serde(default = "default_filename_log")]
    pub filename_log: String,
    /// Logs directory
    ///
    /// By default it will be logs/ of the current directory.
    /// It must end with a / to be a valid folder.
    #[clap(long, default_value_t = default_logs_path())]
    #[serde(default = "default_logs_path")]
    pub logs_path: String,
    /// Module configuration for logs
    #[clap(long)]
    #[serde(default)]
    pub logs_modules: Vec<ModuleConfig>,
    /// Disable the ascii art at startup
    #[clap(long)]
    #[serde(default)]
    pub disable_ascii_art: bool,
    /// Change the datetime format used by the logger
    #[clap(long, default_value_t = default_logs_datetime_format())]
    #[serde(default = "default_logs_datetime_format")]
    pub datetime_format: String,
}

#[derive(clap::Parser, Serialize, Deserialize)]
#[clap(version = VERSION, about = "XELIS is an innovative cryptocurrency built from scratch with BlockDAG, Homomorphic Encryption, Zero-Knowledge Proofs, and Smart Contracts.")]
#[command(styles = xelis_common::get_cli_styles())]
pub struct CliConfig {
    /// Blockchain core configuration
    #[structopt(flatten)]
    pub core: InnerConfig,
    /// Sled DB Backend if enabled
    #[cfg(feature = "sled")]
    #[clap(flatten)]
    #[serde(default)]
    pub sled: SledConfig,
    /// RocksDB Backend if enabled
    #[cfg(feature = "rocksdb")]
    #[clap(flatten)]
    #[serde(default)]
    pub rocksdb: RocksDBConfig,
    /// Use a different DB backend from the default.
    /// Note that the data will not be migrated from one to another
    /// and you may lose your data.
    #[clap(long, value_enum, default_value_t)]
    #[serde(default)]
    pub use_db_backend: StorageBackend,
    /// Log configuration
    #[structopt(flatten)]
    pub log: LogConfig,
    /// Network selected for chain
    #[clap(long, value_enum, default_value_t = Network::Mainnet)]
    #[serde(default)]
    pub network: Network,
    /// JSON File to load the configuration from
    #[clap(long)]
    #[serde(skip)]
    #[serde(default)]
    pub config_file: Option<String>,
    /// Generate the template at the `config_file` path
    #[clap(long)]
    #[serde(skip)]
    #[serde(default)]
    pub generate_config_template: bool,
}
