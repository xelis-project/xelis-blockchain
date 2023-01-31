pub mod command;
pub mod argument;

use self::command::{CommandManager, CommandError};
use std::io::{Write, stdout, Error as IOError};
use fern::colors::{ColoredLevelConfig, Color};
use tokio::sync::mpsc;
use std::sync::{PoisonError, Arc, Mutex};
use log::{info, error, Level, debug};
use tokio::time::interval;
use std::future::Future;
use std::time::Duration;
use thiserror::Error;

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
}

impl Prompt {
    pub fn new(debug: bool, filename_log: String, disable_file_logging: bool) -> Result<Arc<Self>, PromptError>  {
        let v = Self {
            prompt: Mutex::new(None)
        };
        let prompt = Arc::new(v);
        Arc::clone(&prompt).setup_logger(debug, filename_log, disable_file_logging)?;
        Ok(prompt)
    }

    pub async fn start<Fut, T: Clone + Send>(self: &Arc<Self>, update_every: Duration, fn_message: &dyn Fn() -> Fut, command_manager: CommandManager<T>) -> Result<(), PromptError>
    where Fut: Future<Output = String> {
        let mut interval = interval(update_every);
        let zelf = Arc::clone(self);
        // spawn a thread to prevent IO blocking - https://github.com/tokio-rs/tokio/issues/2466
        let (input_sender, mut input_receiver) = mpsc::unbounded_channel::<String>();
        std::thread::spawn(move || {
            let stdin = std::io::stdin();
            loop {
                let mut line = String::new();
                match stdin.read_line(&mut line) {
                    Ok(0) => {
                        break;
                    },
                    Ok(1) => {
                        if let Err(e) = zelf.show() {
                            error!("Error while showing prompt: {}", e);
                        }
                    },
                    Ok(_) => {
                        if let Err(e) = input_sender.send(line) {
                            error!("Error while sending input to command handler: {}", e);
                        }
                    },
                    Err(e) => {
                        error!("Error while reading from stdin: {}", e);
                        break;
                    }
                }
            }
            info!("Command Manager is now stopped");
        });

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

    pub fn show(&self) -> Result<(), PromptError> {
        if let Some(msg) = self.prompt.lock()?.as_ref() {
            print!("\r{}", msg);
            stdout().flush()?;
        }
        Ok(())
    }

    // configure fern and print prompt message after each new output
    fn setup_logger(self: Arc<Self>, debug: bool, filename_log: String, disable_file_logging: bool) -> Result<(), fern::InitError> {
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
                    "\r\x1B[90m{} {}\x1B[0m \x1B[{}m{}\x1B[0m \x1B[90m>\x1B[0m {}",
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

        base = if debug {
            base.level(log::LevelFilter::Debug)
        } else {
            base.level(log::LevelFilter::Info)
        };
        base.apply()?;
        Ok(())
    }

    pub fn colorize_string(color: Color, message: &String) -> String {
        format!("\x1B[{}m{}\x1B[0m", color.to_fg_str(), message)
    }

    pub fn colorize_str(color: Color, message: &str) -> String {
        format!("\x1B[{}m{}\x1B[0m", color.to_fg_str(), message)
    }
}