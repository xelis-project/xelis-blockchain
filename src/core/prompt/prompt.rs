use super::command::CommandManager;
use std::io::{Write, stdout, Error as IOError};
use log::{debug, info, error, Level};
use fern::colors::{ColoredLevelConfig, Color};
use std::sync::{Arc, Mutex};
use std::sync::PoisonError;
use thiserror::Error;
use tokio::io::stdin;
use tokio::io::AsyncReadExt;


#[derive(Error, Debug)]
pub enum PromptError {
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

// TODO build & use history using arrow keys & create a command manager
pub struct Prompt {
    prompt: Mutex<Option<String>>,
    history: Mutex<Vec<String>>,
}

impl Prompt {
    pub fn new(debug: bool, disable_file_logging: bool, command_manager: CommandManager) -> Result<Arc<Self>, PromptError>  {
        let v = Self {
            prompt: Mutex::new(None),
            history: Mutex::new(Vec::new()),
        };
        let prompt = Arc::new(v);
        prompt.clone().setup_logger(debug, disable_file_logging)?;
        let zelf = Arc::clone(&prompt);
        tokio::spawn(async move {
            if let Err(e) = zelf.handle_commands(command_manager).await {
                error!("Error while handling commands: {}", e);
            }
        });
        Ok(prompt)
    }

    pub fn update_prompt(&self, prompt: Option<String>) -> Result<(), PromptError> {
        *self.prompt.lock()? = prompt;
        self.show()
    }

    async fn handle_commands(&self, command_manager: CommandManager) -> Result<(), PromptError> {
        let mut stdin = stdin();
        let mut buf: [u8; 256] = [0; 256];
        loop {
            let n = stdin.read(&mut buf).await?;
            if n == 0 {
                info!("read 0 bytes, exiting");
                break;
            }

            if n > 1 { // don't waste time on empty cmds
                debug!("read {} bytes: {:?}", n, &buf[0..n]);
                let cmd = String::from_utf8_lossy(&buf[0..n-1]); // - 1 is for enter key
                if let Err(e) = command_manager.handle_command(cmd.to_string()) {
                    error!("Error on command: {}", e);
                }
            } else {
                self.show()?;
            }
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