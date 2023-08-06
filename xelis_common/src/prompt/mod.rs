pub mod command;
pub mod argument;

use self::command::{CommandManager, CommandError};
use std::collections::VecDeque;
use std::fmt::{Display, Formatter, self};
use std::io::{Write, stdout, Error as IOError};
use std::str::FromStr;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::terminal;
use fern::colors::{ColoredLevelConfig, Color};
use tokio::sync::mpsc::{self, UnboundedSender};
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
}

impl<T> From<PoisonError<T>> for PromptError {
    fn from(err: PoisonError<T>) -> Self {
        Self::PoisonError(format!("{}", err))
    }
}

pub struct Prompt {
    prompt: Mutex<Option<String>>,
    user_input: Mutex<String>
}

impl Prompt {
    pub fn new(level: LogLevel, filename_log: String, disable_file_logging: bool) -> Result<Arc<Self>, PromptError>  {
        let v = Self {
            prompt: Mutex::new(None),
            user_input: Mutex::new(String::new())
        };
        let prompt = Arc::new(v);
        Arc::clone(&prompt).setup_logger(level, filename_log, disable_file_logging)?;
        Ok(prompt)
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
                        Event::Resize(_, _) => {
                            self.show()?;
                        }
                        Event::Paste(s) => {
                            is_in_history = false;
                            let mut buffer = self.user_input.lock()?;
                            buffer.push_str(&s);
                        }
                        Event::Key(key) => {
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

                                    // user just pressed enter, don't send it and just refresh prompt
                                    if buffer.len() == 0 {
                                        self.show_input(&buffer)?;
                                    } else {
                                        let cloned_buffer = buffer.clone();
                                        buffer.clear();
                                        self.show_input(&buffer)?;

                                        // Save in history & Send the message
                                        history.push_front(cloned_buffer.clone());
                                        if let Err(e) = sender.send(cloned_buffer) {
                                            error!("Error while sending input to command handler: {}", e);
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

        info!("Command Manager is now stopped");
        Ok(())
    }

    pub async fn start<Fut, T: Send>(self: &Arc<Self>, update_every: Duration, fn_message: &dyn Fn() -> Fut, command_manager: CommandManager<T>) -> Result<(), PromptError>
    where Fut: Future<Output = String> {
        if let Err(e) = terminal::enable_raw_mode() {
            error!("Error while enabling raw mode: {}", e);
        }

        let mut interval = interval(update_every);
        // spawn a thread to prevent IO blocking - https://github.com/tokio-rs/tokio/issues/2466
        let (input_sender, mut input_receiver) = mpsc::unbounded_channel::<String>();
        {
            let zelf = Arc::clone(self);
            std::thread::spawn(move || {
                if let Err(e) = zelf.ioloop(input_sender) {
                    error!("Error in ioloop: {}", e);
                };
            });
        }

        loop {
            tokio::select! {
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
                        Some(input) => match command_manager.handle_command(input).await {
                            Err(CommandError::Exit) => break,
                            Err(e) => {
                                error!("Error while executing command: {}", e);
                            }
                            _ => {},
                        },
                        None => { // if None, it means the sender has been dropped (and so, the thread is stopped)
                            debug!("Command Manager has been stopped");
                            break;
                        }
                    }
                }
                _ = interval.tick() => {
                    let prompt = (fn_message)().await;
                    self.update_prompt(prompt)?;
                }
            }
        }

        terminal::disable_raw_mode()?;

        Ok(())
    }

    pub fn update_prompt(&self, msg: String) -> Result<(), PromptError> {
        let mut prompt = self.prompt.lock()?;
        let old = prompt.replace(msg);
        if *prompt != old {
            drop(prompt);
            self.show()?;
        }
        Ok(())
    }

    fn show_with_prompt_and_input(&self, prompt: &String, input: &String) -> Result<(), PromptError> {
        print!("\r\x1B[K{}{}", prompt, input);
        stdout().flush()?;
        Ok(())
    }

    pub fn show_input(&self, input: &String) -> Result<(), PromptError> {
        let default_value = String::new();
        let lock = self.prompt.lock()?;
        let prompt = lock.as_ref().unwrap_or(&default_value);
        self.show_with_prompt_and_input(prompt, input)
    }

    pub fn show(&self) -> Result<(), PromptError> {
        let input = self.user_input.lock()?;
        self.show_input(&input)
    }

    // configure fern and print prompt message after each new output
    fn setup_logger(self: Arc<Self>, level: LogLevel, filename_log: String, disable_file_logging: bool) -> Result<(), fern::InitError> {
        let colors = ColoredLevelConfig::new()
            .debug(Color::Green)
            .info(Color::Cyan)
            .warn(Color::Yellow)
            .error(Color::Red);
        let base = fern::Dispatch::new();
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
                if let Err(e) = self.show() {
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

    pub fn colorize_string(color: Color, message: &String) -> String {
        format!("\x1B[{}m{}\x1B[0m", color.to_fg_str(), message)
    }

    pub fn colorize_str(color: Color, message: &str) -> String {
        format!("\x1B[{}m{}\x1B[0m", color.to_fg_str(), message)
    }
}