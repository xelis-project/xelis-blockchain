pub mod command;
pub mod argument;
pub mod art;

mod error;
mod option;
mod state;

use crate::{
    tokio::{
        spawn_task,
        task::JoinHandle,
        sync::{
            mpsc::{
                self,
                UnboundedReceiver,
                Sender,
                Receiver
            },
            oneshot,
            Mutex as AsyncMutex
        },
        time::{interval, timeout}
    },
    crypto::Hash,
    serializer::Serializer,
};
use std::{
    fmt::{self, Display, Formatter},
    fs::{self, create_dir_all},
    future::Future,
    io,
    path::Path,
    pin::Pin,
    str::FromStr,
    sync::{
        atomic::Ordering,
        Arc,
        Mutex,
    },
    time::Duration
};
use crossterm::terminal;
use self::command::{CommandError, CommandManager};
use anyhow::Error;
use fern::colors::ColoredLevelConfig;
use log::{debug, error, info, trace, warn, Level, LevelFilter};
use serde::{Serialize, Deserialize};
use state::State;
use option::OptionReader;

// Re-export fern and colors
pub use fern::colors::Color;
pub use error::PromptError;

pub const DEFAULT_LOGS_DATETIME_FORMAT: &str = "[%Y-%m-%d] (%H:%M:%S%.3f)";

pub fn default_logs_datetime_format() -> String {
    DEFAULT_LOGS_DATETIME_FORMAT.to_string()
}

// used for launch param
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum LogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace
}

impl Default for LogLevel {
    fn default() -> Self {
        Self::Info
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleConfig {
    pub module: String,
    pub level: LogLevel
}

impl FromStr for ModuleConfig {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split('=');
        let module = parts.next().ok_or("Invalid module")?.to_string();
        let level = parts.next().ok_or("Invalid level")?.parse()?;
        Ok(Self {
            module,
            level
        })
    }
}

impl From<LogLevel> for LevelFilter {
    fn from(value: LogLevel) -> Self {
        match value {
            LogLevel::Off => Self::Off,
            LogLevel::Error => Self::Error,
            LogLevel::Warn => Self::Warn,
            LogLevel::Info => Self::Info,
            LogLevel::Debug => Self::Debug,
            LogLevel::Trace => Self::Trace
        }
    }
}

impl From<LogLevel> for Level {
    fn from(value: LogLevel) -> Self {
        match value {
            LogLevel::Off => Self::Trace,
            LogLevel::Error => Self::Error,
            LogLevel::Warn => Self::Warn,
            LogLevel::Info => Self::Info,
            LogLevel::Debug => Self::Debug,
            LogLevel::Trace => Self::Trace
        }
    }
}

impl Display for LogLevel {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let str = match &self {
            Self::Off => "off",
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        };
        write!(f, "{}", str)
    }
}

impl FromStr for LogLevel {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "error" => Self::Error,
            "warn" => Self::Warn,
            "info" => Self::Info,
            "debug" => Self::Debug,
            "trace" => Self::Trace,
            "off" => Self::Off,
            _ => return Err("Invalid log level")
        })
    }
}

pub struct Prompt {
    state: Arc<State>,
    input_receiver: Mutex<Option<UnboundedReceiver<String>>>,
    // This following channel is used to cancel the read_input method
    read_input_sender: Sender<()>,
    read_input_receiver: AsyncMutex<Receiver<()>>,
    // Should we set colors or not
    disable_colors: bool,
    // Handle to compress the log file
    compression_handle: Option<JoinHandle<()>>
}

pub type ShareablePrompt = Arc<Prompt>;

type LocalBoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;
type AsyncF<'a, T1, T2, R> = Box<dyn Fn(&'a T1, T2) -> LocalBoxFuture<'a, R> + 'a>;

pub fn is_maybe_dir(path: &str) -> bool {
    path.ends_with("/") || path.ends_with("\\")
}

impl Prompt {
    pub fn new(
        level: LogLevel,
        dir_path: &str,
        filename_log: &str,
        disable_file_logging: bool,
        disable_file_log_date_based: bool,
        disable_colors: bool,
        enable_auto_compress_logs: bool,
        interactive: bool,
        module_logs: Vec<ModuleConfig>,
        file_level: LogLevel,
        show_ascii: bool,
        logs_datetime_format: String,
    ) -> Result<ShareablePrompt, PromptError> {
        if !is_maybe_dir(dir_path) {
            return Err(PromptError::LogsPathNotFolder);
        }

        let (read_input_sender, read_input_receiver) = mpsc::channel(1);
        let mut prompt = Self {
            state: Arc::new(State::new(interactive)),
            input_receiver: Mutex::new(None),
            read_input_receiver: AsyncMutex::new(read_input_receiver),
            read_input_sender,
            disable_colors,
            compression_handle: None
        };

        if enable_auto_compress_logs && disable_file_log_date_based {
            return Err(PromptError::AutoCompressParam)
        }

        if is_maybe_dir(filename_log) {
            return Err(PromptError::FileNotDir);
        }

        prompt.setup_logger(
            level,
            dir_path,
            filename_log,
            disable_file_logging,
            disable_file_log_date_based,
            enable_auto_compress_logs,
            module_logs,
            file_level,
            logs_datetime_format,
        )?;

        // Logs all the panics into the log file
        log_panics::init();

        #[cfg(feature = "tracing")]
        {
            info!("Tracing enabled");
            console_subscriber::Builder::default()
                .event_buffer_capacity(console_subscriber::ConsoleLayer::DEFAULT_EVENT_BUFFER_CAPACITY * 2000)
                .client_buffer_capacity(console_subscriber::ConsoleLayer::DEFAULT_CLIENT_BUFFER_CAPACITY * 2000)
                .init();
        }

        if prompt.state.is_interactive() {
            let (input_sender, input_receiver) = mpsc::unbounded_channel::<String>();
            let state = Arc::clone(&prompt.state);
            // spawn a thread to prevent IO blocking - https://github.com/tokio-rs/tokio/issues/2466
            std::thread::spawn(move || {
                if let Err(e) = state.ioloop(input_sender) {
                    error!("Error in ioloop: {}", e);
                };
            });
    
            let mut lock = prompt.input_receiver.lock()?;
            *lock = Some(input_receiver);
        }

        if show_ascii {
            info!("{}", art::LOGO_ASCII);
        }

        Ok(Arc::new(prompt))
    }

    #[cfg(target_os = "windows")]
    pub fn adjust_win_console(&self) -> Result<(), Error> {
        let console = win32console::console::WinConsole::input();
        let mut mode = console.get_mode()?;
        mode = (mode & !win32console::console::ConsoleMode::ENABLE_QUICK_EDIT_MODE)
            | win32console::console::ConsoleMode::ENABLE_EXTENDED_FLAGS;
        console.set_mode(mode)?;
        Ok(())
    }

    // Start the thread to read stdin and handle events
    // Execute commands if a commande manager is present
    pub async fn start<'a>(&'a self, update_every: Duration, fn_message: AsyncF<'a, Self, Option<&'a CommandManager>, Result<String, PromptError>>, command_manager: Option<&'a CommandManager>) -> Result<(), PromptError>
    {
        // setup the exit channel
        let mut exit_receiver = {
            let (sender, receiver) = oneshot::channel();
            self.state.set_exit_channel(sender)?;
            receiver
        };

        let mut input_receiver = OptionReader::new({
            let mut lock = self.input_receiver.lock()?;
            lock.take()
        });

        let mut interval = interval(update_every);
        loop {
            tokio::select! {
                _ = &mut exit_receiver => {
                    info!("Received exit signal, exiting...");
                    break;
                },
                res = tokio::signal::ctrl_c() => {
                    if let Err(e) = res {
                        error!("Error received on CTRL+C: {}", e);
                    } else {
                        info!("CTRL+C received, exiting...");
                    }
                    break;
                },
                Some(input) = &mut input_receiver => {
                    if let Some(command_manager) = command_manager.as_ref() {
                        match command_manager.handle_command(input).await {
                            Err(CommandError::Exit) => break,
                            Err(e) => {
                                error!("Error while executing command: {:#}", e);
                            }
                            _ => {},
                        }
                    } else {
                        debug!("You said '{}'", input);
                    }
                }
                _ = interval.tick() => {
                    {
                        // verify that interactive is enabled and we don't have any reader
                        // as they may have changed the prompt
                        if !self.state.is_interactive() || self.state.get_prompt_sender().lock()?.is_some() {
                            continue;
                        }
                    }
                    match timeout(Duration::from_secs(5), (*fn_message)(&self, command_manager)).await {
                        Ok(res) => {
                            let prompt = res?;
                            self.update_prompt(prompt)?;
                        }
                        Err(e) => {
                            warn!("Couldn't update prompt message: {}", e);
                        }
                    };
                }
            }
        }

        if !self.state.exit().swap(true, Ordering::SeqCst) {
            if self.state.is_interactive() {
                if let Err(e) = terminal::disable_raw_mode() {
                    error!("Error while disabling raw mode: {}", e);
                }
            }
        }

        if let Some(handle) = self.compression_handle.as_ref() {
            handle.abort();
        }

        Ok(())
    }

    // Stop the prompt running
    // can only be called when it was already started
    pub fn stop(&self) -> Result<(), PromptError> {
        self.state.stop()
    }

    pub fn update_prompt(&self, msg: String) -> Result<(), PromptError> {
        let mut prompt = self.state.get_prompt().lock()?;
        let old = prompt.replace(msg);
        if *prompt != old {
            drop(prompt);
            self.state.show()?;
        }
        Ok(())
    }

    fn set_prompt(&self, prompt: Option<String>) -> Result<(), PromptError> {
        {
            let mut lock = self.state.get_prompt().lock()?;
            *lock = prompt;
        }
        self.state.show()?;

        Ok(())
    }

    // get the current prompt displayed
    pub fn get_prompt(&self) -> Result<Option<String>, PromptError> {
        let prompt = self.state.get_prompt().lock()?;
        Ok(prompt.clone())
    }

    // Rewrite the prompt in the terminal with the user input
    pub fn refresh_prompt(&self) -> Result<(), PromptError> {
        self.state.show()
    }

    // Read value from the user and check if it is a valid value (in lower case only)
    pub async fn read_valid_str_value(&self, mut prompt: String, valid_values: &[&str]) -> Result<String, PromptError> {
        let original_prompt = prompt.clone();
        loop {
            let input = self.read_input(prompt, false).await?.to_lowercase();
            if valid_values.contains(&input.as_str()) {
                return Ok(input);
            }
            let escaped_colors = self.state.get_ascii_escape_regex().replace_all(&original_prompt, "");
            prompt = self.colorize_string(Color::Red, &escaped_colors.into_owned());
        }
    }

    // Ask the user for a confirmation (Y/N)
    pub async fn ask_confirmation(&self) -> Result<bool, PromptError> {
        let res = self.read_valid_str_value(
            self.colorize_string(Color::Green, "Confirm ? (Y/N): "),
            &["y", "n"]
        ).await?;
        Ok(res == "y")
    }

    pub async fn read<F: FromStr, S: ToString>(&self, prompt: S) -> Result<F, PromptError>
    where
        <F as FromStr>::Err: Display
    {
        let value = self.read_input(prompt, false).await?;
        value.parse().map_err(|e: F::Err| PromptError::ParseInputError(e.to_string()))
    }

    pub async fn read_hash<S: ToString>(&self, prompt: S) -> Result<Hash, PromptError> {
        let hash_hex = self.read_input(prompt, false).await?;
        Ok(Hash::from_hex(&hash_hex)?)
    }

    pub async fn cancel_read_input(&self) -> Result<(), Error> {
        self.read_input_sender.send(()).await?;
        Ok(())
    }

    // read a message from the user and apply the input mask if necessary
    pub async fn read_input<S: ToString>(&self, prompt: S, apply_mask: bool) -> Result<String, PromptError> {
        // This is also used as a sempahore to have only one call at a time
        let mut canceler = self.read_input_receiver.lock().await;

        // Verify that during the time it hasn't exited
        if self.state.exit().load(Ordering::SeqCst) {
            return Err(PromptError::NotRunning)
        }

        // register our reader
        let (previous, receiver) = {
            let mut prompt_sender = self.state.get_prompt_sender().lock()?;
            let (sender, receiver) = oneshot::channel();
            let prev = prompt_sender.replace(sender);
            (prev, receiver)
        };

        // keep in memory the previous prompt
        let old_prompt = self.get_prompt()?;
        let old_user_input = {
            let mut user_input = self.state.get_user_input().lock()?;
            let cloned = user_input.clone();
            user_input.clear();
            cloned
        };

        if apply_mask {
            self.set_mask_input(true);
        }

        // update the prompt to the requested one and keep blocking on the receiver
        self.update_prompt(prompt.to_string())?;
        let input = tokio::select! {
            Some(()) = canceler.recv() => Err(PromptError::Canceled),
            res = receiver => res.map_err(|_| PromptError::EndOfStream)
        };

        if apply_mask {
            self.set_mask_input(false);
        }

        // set the old prompt
        {
            let mut lock = self.state.get_prompt_sender().lock()?;
            *lock = previous;
        }

        // set the old user input
        {
            let mut user_input = self.state.get_user_input().lock()?;
            *user_input = old_user_input;
        }

        
        self.set_prompt(old_prompt)?;
        self.state.show()?;

        input
    }

    // should we replace user input by * ?
    pub fn should_mask_input(&self) -> bool {
        self.state.should_mask_input()
    }

    // set the value to replace user input by * chars or not
    pub fn set_mask_input(&self, value: bool) {
        self.state.get_mask_input().store(value, Ordering::SeqCst);
    }

    // configure fern and print prompt message after each new output
    fn setup_logger(
        &mut self,
        level: LogLevel,
        dir_path: &str,
        filename_log: &str,
        disable_file_logging: bool,
        disable_file_log_date_based: bool,
        enable_auto_compress_logs: bool,
        module_logs: Vec<ModuleConfig>,
        file_level: LogLevel,
        logs_datetime_format: String,
    ) -> Result<(), fern::InitError> {
        let colors = ColoredLevelConfig::new()
            .debug(Color::Green)
            .info(Color::Cyan)
            .warn(Color::Yellow)
            .error(Color::Red);

        let base = fern::Dispatch::new();

        let disable_colors = self.disable_colors;
        let interactive = self.state.is_interactive();
        let state = Arc::clone(&self.state);
        let stdout_log = fern::Dispatch::new()
            .format(move |out, message, record| {
                let target = record.target();
                let mut target_with_pad = " ".repeat((30i16 - target.len() as i16).max(0) as usize) + target;
                if record.level() != Level::Error && record.level() != Level::Debug {
                    target_with_pad = " ".to_owned() + &target_with_pad;
                }

                let res = if disable_colors {
                    out.finish(format_args!(
                        "\x1b[2K{}{} {}{} > {}",
                        if interactive { "\r" } else { "" },
                        chrono::Local::now().format(&logs_datetime_format),
                        record.level(),
                        target_with_pad,
                        message
                    ))
                } else {
                    let messages = message.to_string()
                        .lines()
                        .map(|line| {
                            format!(
                                "\x1b[2K{}\x1B[90m{} {}\x1B[0m \x1B[{}m{}\x1B[0m \x1B[90m>\x1B[0m {}",
                                if interactive { "\r" } else { "" },
                                chrono::Local::now().format(&logs_datetime_format),
                                colors.color(record.level()),
                                Color::BrightBlue.to_fg_str(),
                                target_with_pad,
                                line
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n");
                    out.finish(format_args!("{}", messages))
                };

                if interactive {
                    state.mark_dirty();
                    if let Err(e) = state.show() {
                        error!("Error on prompt refresh: {}", e);
                    }
                }

                res
            })
            .chain(std::io::stdout())
            .level(level.into());

        let mut base = base.chain(stdout_log);
        if !disable_file_logging {
            let logs_path = Path::new(dir_path);
            if !logs_path.exists() {
                create_dir_all(logs_path)?;
            }

            let mut file_log = fern::Dispatch::new()
            .level(file_level.into())
            .format(move |out, message, record| {
                let pad = " ".repeat((30i16 - record.target().len() as i16).max(0) as usize);
                let level_pad = if record.level() == Level::Error || record.level() == Level::Debug { "" } else { " " };
                let messages = message.to_string()
                    .lines()
                    .map(|line| {
                        format!(
                            "{} [{}{}] [{}]{} | {}",
                            chrono::Local::now().format("[%Y-%m-%d] (%H:%M:%S%.3f)"),
                            record.level(),
                            level_pad,
                            record.target(),
                            pad,
                            line
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                out.finish(format_args!("{}", messages))
            });

            // Don't rotate the log file based on date ourself if its disabled
            if !disable_file_log_date_based {
                let suffix = format!("%Y-%m-%d.{filename_log}");
                file_log = file_log.chain(fern::DateBased::new(logs_path, suffix.clone()));

                // Start a thread to compress the log file
                if enable_auto_compress_logs {
                    let dir_path = dir_path.to_string();
                    let handle = spawn_task("loop-compress-log", async move {
                        if let Err(e) = Self::loop_compress_log_file(dir_path, suffix).await {
                            error!("Error while compressing log file: {}", e);
                        }
                    });
    
                    self.compression_handle = Some(handle);
                }
            } else {
                file_log = file_log.chain(fern::log_file(format!("{}/{}", dir_path, filename_log))?)
            }

            base = base.chain(file_log);
        }

        // Default log level modules
        // It can be overriden by the user below
        base = base.level_for("sled", log::LevelFilter::Warn)
            .level_for("actix_server", log::LevelFilter::Warn)
            .level_for("actix_web", log::LevelFilter::Off)
            .level_for("actix_http", log::LevelFilter::Off)
            .level_for("mio", log::LevelFilter::Warn)
            .level_for("tokio_tungstenite", log::LevelFilter::Warn)
            .level_for("tungstenite", log::LevelFilter::Warn);

        #[cfg(not(feature = "tracing"))]
        {
            base = base.level_for("tracing", log::LevelFilter::Warn)
                .level_for("runtime", log::LevelFilter::Warn)
                .level_for("tokio", log::LevelFilter::Warn);
        }

        for m in module_logs {
            base = base.level_for(m.module, m.level.into());
        }

        base.apply()?;

        Ok(())
    }

    // Compress the log file
    // Once compressed, the original log file is deleted
    fn zip_log_file(log_file_path: &str, zip_file_path: &str) -> io::Result<()> {
        let file = fs::File::create(zip_file_path)?;
        let mut zip = zip::ZipWriter::new(file);

        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Zstd)
            .large_file(true);

        // Start a new file entry in the zip and stream the input file into it
        zip.start_file(log_file_path, options)?;
        let mut input = fs::File::open(log_file_path)?;
        io::copy(&mut input, &mut zip)?;
        zip.finish()?;

        // Delete the original log file
        fs::remove_file(log_file_path)?;

        Ok(())
    }

    // Compress the log file every day
    // The log file is compressed with the date of the previous day
    async fn loop_compress_log_file(dir_path: String, suffix: String) -> Result<(), anyhow::Error> {
        let mut current = chrono::Local::now()
            .date_naive();

        loop {
            let now = chrono::Local::now()
                .date_naive();
            trace!("Checking if we need to compress log file, current: {}, now: {}", current, now);

            // We need to check that current != now
            // because we don't want to compress the current file
            if current.succ_opt() == Some(now) {
                let filename = current.format(suffix.as_str());
                info!("Compressing log file for {}", filename);
                let path = format!("{}/{}", dir_path, filename);
                if Path::new(&path).exists() {
                    let zip_path = format!("{}.zip", path);
                    if let Err(e) = Self::zip_log_file(&path, &zip_path) {
                        error!("Error on zip log file: {}", e);
                    }
                } else {
                    info!("No log file to compress for {}", filename);
                }

                current = now;
            } else {
                debug!("No need to compress log file for {}", current);
            }

            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    }

    // colorize a string with a specific color
    // if colors are disabled, the message is returned as is
    pub fn colorize_string(&self, color: Color, message: &str) -> String {
        if self.disable_colors {
            return message.to_string();
        }

        format!("\x1B[{}m{}\x1B[0m", color.to_fg_str(), message)
    }
}

impl Drop for Prompt {
    fn drop(&mut self) {
        if self.state.is_interactive() {
            if let Ok(true) = terminal::is_raw_mode_enabled() {
                if let Err(e) = terminal::disable_raw_mode() {
                    error!("Error while forcing to disable raw mode: {}", e);
                }
            } 
        }
    }
}