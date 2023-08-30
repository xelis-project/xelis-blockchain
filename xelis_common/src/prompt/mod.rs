pub mod command;
pub mod argument;

use crate::crypto::hash::Hash;
use crate::serializer::{Serializer, ReaderError};

use self::command::{CommandManager, CommandError};
use std::collections::VecDeque;
use std::fmt::{Display, Formatter, self};
use std::io::{Write, stdout, Error as IOError};
use std::num::ParseFloatError;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering, AtomicUsize};
use crossterm::event::{self, Event, KeyCode, KeyModifiers, KeyEventKind};
use crossterm::terminal;
use fern::colors::{ColoredLevelConfig, Color};
use tokio::sync::mpsc::{self, UnboundedSender, UnboundedReceiver};
use tokio::sync::oneshot;
use std::sync::{PoisonError, Arc, Mutex};
use log::{info, error, Level, debug, LevelFilter};
use tokio::time::interval;
use std::future::Future;
use std::time::Duration;
use thiserror::Error;

// used for launch param
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "clap", derive(clap::ArgEnum))]
pub enum LogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace
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
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "error" => Self::Error,
            "warn" => Self::Warn,
            "info" => Self::Info,
            "debug" => Self::Debug,
            "trace" => Self::Trace,
            _ => return Err("Invalid log level".into())
        })
    }
}

#[derive(Error, Debug)]
pub enum PromptError {
    #[error("End of stream")]
    EndOfStream,
    #[error(transparent)]
    FernError(#[from] fern::InitError),
    #[error(transparent)]
    IOError(#[from] IOError),
    #[error("Poison Error: {}", _0)]
    PoisonError(String),
    #[error("Error while starting, already running")]
    AlreadyRunning,
    #[error("Error while starting, not running")]
    NotRunning,
    #[error("No command manager found")]
    NoCommandManager,
    #[error(transparent)]
    ParseFloatError(#[from] ParseFloatError),
    #[error(transparent)]
    ReaderError(#[from] ReaderError)
}

impl<T> From<PoisonError<T>> for PromptError {
    fn from(err: PoisonError<T>) -> Self {
        Self::PoisonError(format!("{}", err))
    }
}

// State used to be shared between stdin thread and Prompt instance
struct State {
    prompt: Mutex<Option<String>>,
    previous_prompt_line: AtomicUsize,
    user_input: Mutex<String>,
    mask_input: AtomicBool,
    readers: Mutex<Vec<oneshot::Sender<String>>>,
    has_exited: AtomicBool,
}

impl State {
    fn new() -> Self {
        Self {
            prompt: Mutex::new(None),
            previous_prompt_line: AtomicUsize::new(0),
            user_input: Mutex::new(String::new()),
            mask_input: AtomicBool::new(false),
            readers: Mutex::new(Vec::new()),
            has_exited: AtomicBool::new(false),
        }
    }

    fn ioloop(self: &Arc<Self>, sender: UnboundedSender<String>) -> Result<(), PromptError> {
        debug!("ioloop started");
        // enable the raw mode for terminal
        // so we can read each event/action
        if let Err(e) = terminal::enable_raw_mode() {
            error!("Error while enabling raw mode: {}", e);
        }

        // all the history of commands
        let mut history: VecDeque<String> = VecDeque::new();
        // current index in history in case we use arrows to move in history
        let mut history_index = 0;
        let mut is_in_history = false;
        loop {
            if !is_in_history {
                history_index = 0;
            }

            match event::read() {
                Ok(event) => {
                    match event {
                        Event::Resize(_, _) => {
                            self.show()?;
                        }
                        Event::Paste(s) => {
                            is_in_history = false;
                            let mut buffer = self.user_input.lock()?;
                            buffer.push_str(&s);
                        }
                        Event::Key(key) => {
                            // Windows bug - https://github.com/crossterm-rs/crossterm/issues/772
                            if key.kind != KeyEventKind::Press {
                                continue;
                            }

                            match key.code {
                                KeyCode::Up => {
                                    let mut buffer = self.user_input.lock()?;
                                    if buffer.is_empty() {
                                        is_in_history = true;
                                    }

                                    if is_in_history {
                                        if history_index < history.len() {
                                            buffer.clear();
                                            buffer.push_str(&history[history_index]);
                                            self.show_input(&buffer)?;
                                            if history_index + 1 < history.len() {
                                                history_index += 1;
                                            }
                                        }
                                    }
                                },
                                KeyCode::Down => {
                                    if is_in_history {
                                        let mut buffer = self.user_input.lock()?;
                                        buffer.clear();
                                        if history_index > 0 {
                                            history_index -= 1;
                                            if history_index < history.len() {
                                                buffer.push_str(&history[history_index]);
                                            }
                                        } else {
                                            is_in_history = false;
                                        }
                                        self.show_input(&buffer)?;
                                    }
                                },
                                KeyCode::Char(c) => {
                                    is_in_history = false;
                                    // handle CTRL+C
                                    if key.modifiers == KeyModifiers::CONTROL && c == 'c' {
                                        break;
                                    }

                                    let mut buffer = self.user_input.lock()?;
                                    buffer.push(c);
                                    self.show_input(&buffer)?;
                                },
                                KeyCode::Backspace => {
                                    is_in_history = false;
                                    let mut buffer = self.user_input.lock()?;
                                    buffer.pop();

                                    self.show_input(&buffer)?;
                                },
                                KeyCode::Enter => {
                                    is_in_history = false;
                                    let mut buffer = self.user_input.lock()?;

                                    // clone the buffer to send it to the command handler
                                    let cloned_buffer = buffer.clone();
                                    buffer.clear();
                                    self.show_input(&buffer)?;

                                    // Save in history & Send the message
                                    let mut readers = self.readers.lock()?;
                                    if readers.is_empty() {
                                        if !cloned_buffer.is_empty() {
                                            history.push_front(cloned_buffer.clone());
                                            if let Err(e) = sender.send(cloned_buffer) {
                                                error!("Error while sending input to command handler: {}", e);
                                                break;
                                            }
                                        }
                                    } else {
                                        let reader = readers.remove(0);
                                        if let Err(e) = reader.send(cloned_buffer) {
                                            error!("Error while sending input to reader: {}", e);
                                            break;
                                        }
                                    }
                                },
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                },
                Err(e) => {
                    error!("Error while reading input: {}", e);
                    break;
                }
            };
        }

        if !self.has_exited.swap(true, Ordering::SeqCst) {
            if let Err(e) = terminal::disable_raw_mode() {
                error!("Error while disabling raw mode: {}", e);
            }
        }

        info!("ioloop thread is now stopped");
        Ok(())
    }

    fn should_mask_input(&self) -> bool {
        self.mask_input.load(Ordering::SeqCst)
    }

    fn show_with_prompt_and_input(&self, prompt: &String, input: &String) -> Result<(), PromptError> {
        let lines_count = prompt.lines().count();
        let previous_lines_count = self.previous_prompt_line.swap(lines_count, Ordering::SeqCst);
        let lines_eraser = if previous_lines_count > 1 {
            format!("{}", "\x1B[A".repeat(previous_lines_count - 1))
        } else {
            String::new()
        };

        if self.should_mask_input() {
            print!("\r\x1B[2K{}{}{}", lines_eraser, prompt, "*".repeat(input.len()));
        } else {
            print!("\r\x1B[2K{}{}{}", lines_eraser, prompt, input);
        }

        stdout().flush()?;
        Ok(())
    }

    fn show_input(&self, input: &String) -> Result<(), PromptError> {
        let default_value = String::with_capacity(0);
        let lock = self.prompt.lock()?;
        let prompt = lock.as_ref().unwrap_or(&default_value);
        self.show_with_prompt_and_input(prompt, input)
    }

    fn show(&self) -> Result<(), PromptError> {
        let input = self.user_input.lock()?;
        self.show_input(&input)
    }
}

pub struct Prompt<T> {
    state: Arc<State>,
    exit_channel: Mutex<Option<oneshot::Sender<()>>>,
    input_receiver: Mutex<Option<UnboundedReceiver<String>>>,
    command_manager: Mutex<Option<CommandManager<T>>>
}

pub type ShareablePrompt<T> = Arc<Prompt<T>>;

impl<T> Prompt<T> {
    pub fn new(level: LogLevel, filename_log: String, disable_file_logging: bool) -> Result<ShareablePrompt<T>, PromptError> {
        let zelf = Self {
            state: Arc::new(State::new()),
            exit_channel: Mutex::new(None),
            input_receiver: Mutex::new(None),
            command_manager: Mutex::new(None)
        };
        zelf.setup_logger(level, filename_log, disable_file_logging)?;

        // spawn a thread to prevent IO blocking - https://github.com/tokio-rs/tokio/issues/2466
        let (input_sender, input_receiver) = mpsc::unbounded_channel::<String>();
        {
            let state = Arc::clone(&zelf.state);
            std::thread::spawn(move || {
                if let Err(e) = state.ioloop(input_sender) {
                    error!("Error in ioloop: {}", e);
                };
            });
        }

        {
            let mut lock = zelf.input_receiver.lock()?;
            *lock = Some(input_receiver);
        }

        Ok(Arc::new(zelf))
    }

    // Set a new commander manager
    pub fn set_command_manager(&self, command_manager: Option<CommandManager<T>>) -> Result<(), PromptError> {
        let mut lock = self.command_manager.lock()?;
        *lock = command_manager;

        Ok(())
    }

    // get a mutable (if necessary) reference of CommandManager
    pub fn get_command_manager(&self) -> &Mutex<Option<CommandManager<T>>> {
        &self.command_manager
    }

    // Display all available commands if CommandManager is available
    pub fn display_commands(&self) -> Result<(), PromptError> {
        let command_manager = self.command_manager.lock()?;
        if let Some(manager) = command_manager.as_ref() {
            for cmd in manager.get_commands() {
                manager.message(format!("- {}: {}", cmd.get_name(), cmd.get_description()));
            }

            Ok(())
        } else {
            Err(PromptError::NoCommandManager)
        }
    }

    // Start the thread to read stdin and handle events
    // Execute commands if a commande manager is present
    pub async fn start<'a, Fut>(&'a self, update_every: Duration, fn_message: &'a dyn Fn(&'a Self) -> Fut) -> Result<(), PromptError>
        where Fut: Future<Output = Result<String, PromptError>> + 'a
    {
        // setup the exit channel
        let mut exit_receiver = {
            let mut exit = self.exit_channel.lock()?;
            if exit.is_some() {
                return Err(PromptError::AlreadyRunning)
            }
            let (sender, receiver) = oneshot::channel();
            *exit = Some(sender);
            receiver
        };

        let mut input_receiver = {
            let mut lock = self.input_receiver.lock()?;
            lock.take().ok_or(PromptError::NotRunning)?
        };

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
                res = input_receiver.recv() => {
                    match res {
                        Some(input) => {
                            if let Some(command_manager) = self.command_manager.lock()?.as_ref() {
                                match command_manager.handle_command(input).await {
                                    Err(CommandError::Exit) => break,
                                    Err(e) => {
                                        error!("Error while executing command: {}", e);
                                    }
                                    _ => {},
                                }
                            } else {
                                debug!("You said '{}'", input);
                            }
                        },
                        None => { // if None, it means the sender has been dropped (and so, the thread is stopped)
                            debug!("Command Manager has been stopped");
                            break;
                        }
                    }
                }
                _ = interval.tick() => {
                    {
                        // verify that we don't have any readers
                        // as they may have changed the prompt
                        let readers = self.state.readers.lock()?;
                        if !readers.is_empty() {
                            continue;
                        }
                    }
                    let prompt = (fn_message)(self).await?;
                    self.update_prompt(prompt)?;
                }
            }
        }

        if !self.state.has_exited.swap(true, Ordering::SeqCst) {
            if let Err(e) = terminal::disable_raw_mode() {
                error!("Error while disabling raw mode: {}", e);
            }
        }

        Ok(())
    }

    // Stop the prompt running
    // can only be called when it was already started
    pub fn stop(&self) -> Result<(), PromptError> {
        let mut exit = self.exit_channel.lock()?;
        let sender = exit.take().ok_or(PromptError::NotRunning)?;

        if sender.send(()).is_err() {
            error!("Error while sending exit signal");
        }

        Ok(())
    }

    pub fn update_prompt(&self, msg: String) -> Result<(), PromptError> {
        let mut prompt = self.state.prompt.lock()?;
        let old = prompt.replace(msg);
        if *prompt != old {
            drop(prompt);
            self.state.show()?;
        }
        Ok(())
    }

    fn set_prompt(&self, prompt: Option<String>) -> Result<(), PromptError> {
        {
            let mut lock = self.state.prompt.lock()?;
            *lock = prompt;
        }
        self.state.show()?;

        Ok(())
    }

    // get the current prompt displayed
    pub fn get_prompt(&self) -> Result<Option<String>, PromptError> {
        let prompt = self.state.prompt.lock()?;
        Ok(prompt.clone())
    }

    // Rewrite the prompt in the terminal with the user input
    pub fn refresh_prompt(&self) -> Result<(), PromptError> {
        self.state.show()
    }

    // Read value from the user and check if it is a valid value (in lower case only)
    pub async fn read_valid_str_value(&self, mut prompt: String, valid_values: Vec<&str>) -> Result<String, PromptError> {
        let original_prompt = prompt.clone();
        loop {
            let input = self.read_input(prompt, false).await?.to_lowercase();
            if valid_values.contains(&input.as_str()) {
                return Ok(input);
            }
            prompt = colorize_string(Color::Red, &original_prompt);
        }
    }

    pub async fn ask_confirmation(&self) -> Result<bool, PromptError> {
        let res = self.read_valid_str_value(
            colorize_str(Color::Green, "Confirm ? (Y/N): "),
            vec!["y", "n"]
        ).await?;
        Ok(res == "y")
    }

    pub async fn read_f64(&self, prompt: String) -> Result<f64, PromptError> {
        let value = self.read_input(prompt, false).await?;
        let float_value = value.parse()?;
        Ok(float_value)
    }

    pub async fn read_hash(&self, prompt: String) -> Result<Hash, PromptError> {
        let hash_hex = self.read_input(prompt, false).await?;
        Ok(Hash::from_hex(hash_hex)?)
    }

    // read a message from the user and apply the input mask if necessary
    pub async fn read_input(&self, prompt: String, apply_mask: bool) -> Result<String, PromptError> {
        // register our reader
        let receiver = {
            let mut readers = self.state.readers.lock()?;
            let (sender, receiver) = oneshot::channel();
            readers.push(sender);
            receiver
        };

        // keep in memory the previous prompt
        let old_prompt = self.get_prompt()?;
        let old_user_input = {
            let mut user_input = self.state.user_input.lock()?;
            let cloned = user_input.clone();
            user_input.clear();
            cloned
        };

        if apply_mask {
            self.set_mask_input(true);
        }

        // update the prompt to the requested one and keep blocking on the receiver
        self.update_prompt(prompt)?;
        let input = receiver.await.map_err(|_| PromptError::EndOfStream)?;

        if apply_mask {
            self.set_mask_input(false);
        }
        
        // set the old user input
        {
            let mut user_input = self.state.user_input.lock()?;
            *user_input = old_user_input;
        }
        self.set_prompt(old_prompt)?;
        self.state.show()?;

        Ok(input)
    }

    // should we replace user input by * ?
    pub fn should_mask_input(&self) -> bool {
        self.state.should_mask_input()
    }

    // set the value to replace user input by * chars or not
    pub fn set_mask_input(&self, value: bool) {
        self.state.mask_input.store(value, Ordering::SeqCst);
    }

    // configure fern and print prompt message after each new output
    fn setup_logger(&self, level: LogLevel, filename_log: String, disable_file_logging: bool) -> Result<(), fern::InitError> {
        let colors = ColoredLevelConfig::new()
            .debug(Color::Green)
            .info(Color::Cyan)
            .warn(Color::Yellow)
            .error(Color::Red);

        let base = fern::Dispatch::new();

        let state = Arc::clone(&self.state);
        let stdout_log = fern::Dispatch::new()
            .format(move |out, message, record| {
                let target = record.target();
                let mut target_with_pad = " ".repeat((30i16 - target.len() as i16).max(0) as usize) + target;
                if record.level() != Level::Error && record.level() != Level::Debug {
                    target_with_pad = " ".to_owned() + &target_with_pad;
                }
                let res = out.finish(format_args!(
                    "\x1b[2K\r\x1B[90m{} {}\x1B[0m \x1B[{}m{}\x1B[0m \x1B[90m>\x1B[0m {}",
                    chrono::Local::now().format("[%Y-%m-%d] (%H:%M:%S%.3f)"),
                    colors.color(record.level()),
                    Color::BrightBlue.to_fg_str(),
                    target_with_pad,
                    message
                ));
                if let Err(e) = state.show() {
                    error!("Error on prompt refresh: {}", e);
                }
                res
            }).chain(std::io::stdout());

        let mut base = base.chain(stdout_log);
        if !disable_file_logging {
            let file_log = fern::Dispatch::new()
            .format(move |out, message, record| {
                let pad = " ".repeat((30i16 - record.target().len() as i16).max(0) as usize);
                let level_pad = if record.level() == Level::Error || record.level() == Level::Debug { "" } else { " " };
                out.finish(format_args!(
                    "{} [{}{}] [{}]{} | {}",
                    chrono::Local::now().format("[%Y-%m-%d] (%H:%M:%S%.3f)"),
                    record.level(),
                    level_pad,
                    record.target(),
                    pad,
                    message
                ))
            }).chain(fern::log_file(filename_log)?);
            base = base.chain(file_log);
        }

        base = base.level(level.into());

        base.level_for("sled", log::LevelFilter::Warn)
        .level_for("actix_server", log::LevelFilter::Warn)
        .level_for("actix_web", log::LevelFilter::Warn)
        .level_for("actix_http", log::LevelFilter::Warn)
        .level_for("mio", log::LevelFilter::Warn)
        .apply()?;

        Ok(())
    }
}

pub fn colorize_string(color: Color, message: &String) -> String {
    format!("\x1B[{}m{}\x1B[0m", color.to_fg_str(), message)
}

pub fn colorize_str(color: Color, message: &str) -> String {
    format!("\x1B[{}m{}\x1B[0m", color.to_fg_str(), message)
}