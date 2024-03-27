pub mod command;
pub mod argument;

use crate::{
    crypto::Hash,
    serializer::{Serializer, ReaderError},
};
use std::{
    collections::VecDeque,
    fmt::{self, Display, Formatter},
    fs::create_dir_all,
    future::Future,
    io::{stdout, Error as IOError, Write},
    path::Path,
    pin::Pin,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering},
        Arc,
        Mutex,
        PoisonError
    },
    task::{Context, Poll},
    time::Duration
};
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers, KeyEventKind},
    terminal as crossterminal,
};
use tokio::{
    sync::{
        mpsc::{self, UnboundedSender, UnboundedReceiver, Sender, Receiver},
        oneshot,
        Mutex as AsyncMutex
    },
    time::{interval, timeout}
};
use self::command::{CommandError, CommandManager};
use anyhow::Error;
use fern::colors::{ColoredLevelConfig, Color};
use regex::Regex;
use log::{info, error, Level, debug, LevelFilter, warn};
use thiserror::Error;

// used for launch param
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
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
    #[error("Canceled read input")]
    Canceled,
    #[error("End of stream")]
    EndOfStream,
    #[error(transparent)]
    FernError(#[from] fern::InitError),
    #[error(transparent)]
    IOError(#[from] IOError),
    #[error("Poison Error: {}", _0)]
    PoisonError(String),
    #[error("Prompt is already running")]
    AlreadyRunning,
    #[error("Prompt is not running")]
    NotRunning,
    #[error("No command manager found")]
    NoCommandManager,
    #[error("Error while parsing: {}", _0)]
    ParseInputError(String),
    #[error(transparent)]
    ReaderError(#[from] ReaderError),
    #[error(transparent)]
    CommandError(#[from] CommandError),
}

impl<T> From<PoisonError<T>> for PromptError {
    fn from(err: PoisonError<T>) -> Self {
        Self::PoisonError(format!("{}", err))
    }
}

// State used to be shared between stdin thread and Prompt instance
struct State {
    prompt: Mutex<Option<String>>,
    exit_channel: Mutex<Option<oneshot::Sender<()>>>,
    width: AtomicU16,
    previous_prompt_line: AtomicUsize,
    user_input: Mutex<String>,
    mask_input: AtomicBool,
    prompt_sender: Mutex<Option<oneshot::Sender<String>>>,
    has_exited: AtomicBool,
    ascii_escape_regex: Regex,
    interactive: bool
}

impl State {
    fn new() -> Self {
        // enable the raw mode for terminal
        // so we can read each event/action
        let interactive = !crossterminal::enable_raw_mode().is_err();
        if interactive {
            warn!("Non-interactive mode enabled");
        }

        Self {
            prompt: Mutex::new(None),
            exit_channel: Mutex::new(None),
            width: AtomicU16::new(crossterminal::size().unwrap_or((80, 0)).0),
            previous_prompt_line: AtomicUsize::new(0),
            user_input: Mutex::new(String::new()),
            mask_input: AtomicBool::new(false),
            prompt_sender: Mutex::new(None),
            has_exited: AtomicBool::new(false),
            ascii_escape_regex: Regex::new("\x1B\\[[0-9;]*[A-Za-z]").unwrap(),
            interactive
        }
    }

    fn set_exit_channel(&self, sender: oneshot::Sender<()>) -> Result<(), PromptError> {
        let mut exit = self.exit_channel.lock()?;
        if exit.is_some() {
            return Err(PromptError::AlreadyRunning)
        }
        *exit = Some(sender);
        Ok(())
    }

    pub fn stop(&self) -> Result<(), PromptError> {
        let mut exit = self.exit_channel.lock()?;
        let sender = exit.take().ok_or(PromptError::NotRunning)?;

        if sender.send(()).is_err() {
            error!("Error while sending exit signal");
        }

        Ok(())
    }

    pub fn is_interactive(&self) -> bool {
        self.interactive
    }

    fn ioloop(self: &Arc<Self>, sender: UnboundedSender<String>) -> Result<(), PromptError> {
        debug!("ioloop started");

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
                        Event::Resize(width, _) => {
                            self.width.store(width, Ordering::SeqCst);
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
                                    let mut prompt_sender = self.prompt_sender.lock()?;
                                    if let Some(sender) = prompt_sender.take() {
                                        if let Err(e) = sender.send(cloned_buffer) {
                                            error!("Error while sending input to reader: {}", e);
                                            break;
                                        }
                                    } else {
                                        if !cloned_buffer.is_empty() {
                                            history.push_front(cloned_buffer.clone());
                                            if let Err(e) = sender.send(cloned_buffer) {
                                                error!("Error while sending input to command handler: {}", e);
                                                break;
                                            }
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
            if self.is_interactive() {
                if let Err(e) = crossterminal::disable_raw_mode() {
                    error!("Error while disabling raw mode: {}", e);
                }
            }
        }

        info!("ioloop thread is now stopped");

        // Send an empty message to the reader to unblock it
        let mut sender = self.prompt_sender.lock()?;
        if let Some(sender) = sender.take() {
            if let Err(e) = sender.send(String::new()) {
                error!("Error while sending input to reader: {}", e);
            }
        }

        self.stop()
    }

    fn should_mask_input(&self) -> bool {
        self.mask_input.load(Ordering::SeqCst)
    }

    fn count_lines(&self, value: &String) -> usize {
        let width = self.width.load(Ordering::SeqCst);

        let mut lines = 0;
        let mut current_line_width = 0;
        let input = self.ascii_escape_regex.replace_all(value, "");

        for c in input.chars() {
            if c == '\n' || current_line_width >= width {
                lines += 1;
                current_line_width = 0;
            } else {
                current_line_width += 1;
            }
        }

        if current_line_width > 0 {
            lines += 1;
        }

        lines
    }

    fn show_with_prompt_and_input(&self, prompt: &String, input: &String) -> Result<(), PromptError> {
        let current_count = self.count_lines(&format!("\r{}{}", prompt, input));
        let previous_count = self.previous_prompt_line.swap(current_count, Ordering::SeqCst);

        // > 1 because prompt line is already counted below
        if self.is_interactive() && previous_count > 1 {
            print!("\x1B[{}A\x1B[J", previous_count - 1);
        }

        if self.should_mask_input() {
            print!("\r\x1B[2K{}{}", prompt, "*".repeat(input.len()));
        } else {
            print!("\r\x1B[2K{}{}", prompt, input);
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

struct OptionReader {
    reader: Option<UnboundedReceiver<String>>
}

impl OptionReader {
    fn new(reader: Option<UnboundedReceiver<String>>) -> Self {
        Self {
            reader
        }
    }
}

impl Future for OptionReader {
    type Output = Option<String>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.reader.as_mut() {
            Some(reader) => {
                match Pin::new(reader).poll_recv(cx) {
                    Poll::Ready(Some(value)) => Poll::Ready(Some(value)),
                    Poll::Ready(None) => Poll::Ready(None),
                    Poll::Pending => Poll::Pending
                }
            },
            None => Poll::Ready(None)
        }
    }
}

pub struct Prompt {
    state: Arc<State>,
    input_receiver: Mutex<Option<UnboundedReceiver<String>>>,
    // This following channel is used to cancel the read_input method
    read_input_sender: Sender<()>,
    read_input_receiver: AsyncMutex<Receiver<()>>
}

pub type ShareablePrompt = Arc<Prompt>;

type LocalBoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;
type AsyncF<'a, T1, T2, R> = Box<dyn Fn(&'a T1, T2) -> LocalBoxFuture<'a, R> + 'a>;

impl Prompt {
    pub fn new(level: LogLevel, dir_path: &String, filename_log: &String, disable_file_logging: bool) -> Result<ShareablePrompt, PromptError> {
        let (read_input_sender, read_input_receiver) = mpsc::channel(1);
        let prompt = Self {
            state: Arc::new(State::new()),
            input_receiver: Mutex::new(None),
            read_input_receiver: AsyncMutex::new(read_input_receiver),
            read_input_sender,
        };
        prompt.setup_logger(level, dir_path, filename_log, disable_file_logging)?;

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

        Ok(Arc::new(prompt))
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
                                error!("Error while executing command: {}", e);
                            }
                            _ => {},
                        }
                    } else {
                        debug!("You said '{}'", input);
                    }
                }
                _ = interval.tick() => {
                    {
                        // verify that we don't have any reader
                        // as they may have changed the prompt
                        if self.state.prompt_sender.lock()?.is_some() {
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

        if !self.state.has_exited.swap(true, Ordering::SeqCst) {
            if self.state.is_interactive() {
                if let Err(e) = crossterminal::disable_raw_mode() {
                    error!("Error while disabling raw mode: {}", e);
                }
            }
        }

        Ok(())
    }

    // Stop the prompt running
    // can only be called when it was already started
    pub fn stop(&self) -> Result<(), PromptError> {
        self.state.stop()
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
            let escaped_colors = self.state.ascii_escape_regex.replace_all(&original_prompt, "");
            prompt = colorize_string(Color::Red, &escaped_colors.into_owned());
        }
    }

    pub async fn ask_confirmation(&self) -> Result<bool, PromptError> {
        let res = self.read_valid_str_value(
            colorize_str(Color::Green, "Confirm ? (Y/N): "),
            vec!["y", "n"]
        ).await?;
        Ok(res == "y")
    }

    pub async fn read<F: FromStr>(&self, prompt: String) -> Result<F, PromptError>
    where
        <F as FromStr>::Err: Display
    {
        let value = self.read_input(prompt, false).await?;
        value.parse().map_err(|e: F::Err| PromptError::ParseInputError(e.to_string()))
    }

    pub async fn read_hash(&self, prompt: String) -> Result<Hash, PromptError> {
        let hash_hex = self.read_input(prompt, false).await?;
        Ok(Hash::from_hex(hash_hex)?)
    }

    pub async fn cancel_read_input(&self) -> Result<(), Error> {
        self.read_input_sender.send(()).await?;
        Ok(())
    }

    // read a message from the user and apply the input mask if necessary
    pub async fn read_input(&self, prompt: String, apply_mask: bool) -> Result<String, PromptError> {
        // This is also used as a sempahore to have only one call at a time
        let mut canceler = self.read_input_receiver.lock().await;

        // Verify that during the time it hasn't exited
        if self.state.has_exited.load(Ordering::SeqCst) {
            return Err(PromptError::NotRunning)
        }

        // register our reader
        let receiver = {
            let mut prompt_sender = self.state.prompt_sender.lock()?;
            let (sender, receiver) = oneshot::channel();
            *prompt_sender = Some(sender);
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
        let input = {
            let input = tokio::select! {
                Some(()) = canceler.recv() => {
                    self.state.prompt_sender.lock()?.take();
                    Err(PromptError::Canceled)
                },
                res = receiver => res.map_err(|_| PromptError::EndOfStream)
            };
            input
        };

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

        input
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
    fn setup_logger(&self, level: LogLevel, dir_path: &String, filename_log: &String, disable_file_logging: bool) -> Result<(), fern::InitError> {
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
            })
            .chain(std::io::stdout())
            .level(level.into());

        let mut base = base.chain(stdout_log);
        if !disable_file_logging {
            let logs_path = Path::new(dir_path);
            if !logs_path.exists() {
                create_dir_all(logs_path)?;
            }

            let file_log = fern::Dispatch::new()
            .level(level.into())
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
            }).chain(fern::DateBased::new(logs_path, format!("%Y-%m-%d.{filename_log}")));
            base = base.chain(file_log);
        }

        base.level_for("sled", log::LevelFilter::Warn)
        .level_for("actix_server", log::LevelFilter::Warn)
        .level_for("actix_web", log::LevelFilter::Warn)
        .level_for("actix_http", log::LevelFilter::Warn)
        .level_for("mio", log::LevelFilter::Warn)
        .level_for("tokio_tungstenite", log::LevelFilter::Warn)
        .level_for("tungstenite", log::LevelFilter::Warn)
        .apply()?;

        Ok(())
    }
}

impl Drop for Prompt {
    fn drop(&mut self) {
        if self.state.is_interactive() {
            if let Ok(true) = crossterminal::is_raw_mode_enabled() {
                if let Err(e) = crossterminal::disable_raw_mode() {
                    error!("Error while forcing to disable raw mode: {}", e);
                }
            } 
        }
    }
}

pub fn colorize_string(color: Color, message: &String) -> String {
    format!("\x1B[{}m{}\x1B[0m", color.to_fg_str(), message)
}

pub fn colorize_str(color: Color, message: &str) -> String {
    format!("\x1B[{}m{}\x1B[0m", color.to_fg_str(), message)
}