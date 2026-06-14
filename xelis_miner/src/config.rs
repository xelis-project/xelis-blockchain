use clap::Parser;
use serde::{Deserialize, Serialize};
use xelis_common::{
    block::Algorithm,
    config::VERSION,
    crypto::Address,
    prompt::{default_logs_datetime_format, LogLevel, ModuleConfig},
};

// Daemon address used when no address is provided.
pub const DEFAULT_DAEMON_ADDRESS: &str = "127.0.0.1:8080";

fn default_daemon_address() -> String {
    DEFAULT_DAEMON_ADDRESS.to_owned()
}

fn default_iterations() -> usize {
    100
}

fn default_log_filename() -> String {
    "xelis-miner.log".to_owned()
}

fn default_logs_path() -> String {
    "logs/".to_owned()
}

fn default_worker_name() -> String {
    "default".to_owned()
}

#[derive(Parser, Serialize, Deserialize)]
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
    /// When enabled, the log file is named `xelis-miner.log` instead of
    /// `YYYY-MM-DD.xelis-miner.log`.
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
    /// Defaults to `xelis-miner.log`. Unless date-based filenames are disabled,
    /// daily log files are named `YYYY-MM-DD.xelis-miner.log`.
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

#[derive(Parser, Serialize, Deserialize)]
pub struct BenchmarkConfig {
    /// Enable benchmark mode for the selected proof-of-work algorithm.
    #[clap(long)]
    pub benchmark: Option<Algorithm>,
    /// Number of proof-of-work iterations to run per benchmark thread count.
    #[clap(long, default_value_t = default_iterations())]
    #[serde(default = "default_iterations")]
    pub iterations: usize,
}

#[derive(Parser, Serialize, Deserialize)]
#[clap(version = VERSION, about = "Connects to a daemon, receives GetWork jobs, and mines blocks for the configured reward address.")]
#[command(styles = xelis_common::get_cli_styles())]
pub struct Config {
    /// Log output configuration.
    #[clap(flatten)]
    pub log: LogConfig,
    /// Benchmark mode settings.
    #[clap(flatten)]
    pub benchmark: BenchmarkConfig,
    /// Wallet address that receives mined block rewards.
    #[clap(short, long)]
    pub miner_address: Option<Address>,
    /// Daemon RPC address used to receive mining work.
    #[clap(long, default_value_t = default_daemon_address())]
    #[serde(default = "default_daemon_address")]
    pub daemon_address: String,
    /// Bind address for the miner stats API.
    #[cfg(feature = "api_stats")]
    #[clap(long)]
    pub api_bind_address: Option<String>,
    /// Number of mining threads to use.
    ///
    /// Defaults to the detected CPU parallelism.
    #[clap(short, long)]
    pub num_threads: Option<u16>,
    /// Worker name displayed by the daemon.
    #[clap(short, long, default_value_t = default_worker_name())]
    #[serde(default = "default_worker_name")]
    pub worker: String,
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
