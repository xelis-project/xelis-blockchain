use super::command::CommandManager;
use std::future::Future;
use std::io::{Write, stdout, Error as IOError};
use fern::colors::{ColoredLevelConfig, Color};
use tokio::io::{AsyncReadExt, stdin};
use log::{debug, error, Level};
use std::sync::{Arc, Mutex};
use std::sync::PoisonError;
use tokio::time::interval;
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
    command_manager: CommandManager
}

impl Prompt {
    pub fn new(debug: bool, disable_file_logging: bool, command_manager: CommandManager) -> Result<Arc<Self>, PromptError>  {
        let v = Self {
            prompt: Mutex::new(None),
            command_manager
        };
        let prompt = Arc::new(v);
        Arc::clone(&prompt).setup_logger(debug, disable_file_logging)?;
        Ok(prompt)
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

    pub async fn handle_commands<Fut>(&self, fn_message: &dyn Fn() -> Fut) -> Result<(), PromptError>
    where Fut: Future<Output = String> {
        let mut interval = interval(Duration::from_millis(100));
        let mut stdin = stdin();
        let mut buf = [0u8; 256]; // alow up to 256 characters
        loop {
            tokio::select! {
                res = stdin.read(&mut buf) => {
                    let n = res?;
                    if n == 0 {
                        return Err(PromptError::EndOfStream);
                    }

                    if n > 1 { // don't waste time on empty cmds
                        debug!("read {} bytes: {:?}", n, &buf[0..n]);
                        let cmd = String::from_utf8_lossy(&buf[0..n-1]); // - 1 is for enter key
                        if let Err(e) = self.command_manager.handle_command(cmd.to_string()) {
                            error!("Error on command: {}", e);
                        }
                    } else {
                        self.show()?;
                    }
                }
                _ = interval.tick() => {
                    let prompt = (fn_message)().await;
                    self.update_prompt(prompt)?;
                }
            }
        }
    }

    pub fn show(&self) -> Result<(), PromptError> {
        if let Some(msg) = self.prompt.lock()?.as_ref() {
            print!("\r{}", msg);
            stdout().flush()?;
        }
        Ok(())
    }

    // configure fern and print prompt message after each new output
    fn setup_logger(self: Arc<Self>, debug: bool, disable_file_logging: bool) -> Result<(), fern::InitError> {
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
            }).chain(fern::log_file("xelis.log")?);
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