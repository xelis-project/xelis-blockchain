use std::io::{Write, stdin, stdout, Error as IOError};
use log::{debug, error, Level};
use fern::colors::{ColoredLevelConfig, Color};
use std::sync::{Arc, Mutex};
use std::sync::PoisonError;
use thiserror::Error;
use std::sync::mpsc::{Sender, Receiver, TryRecvError, channel};
use std::thread;

#[derive(Error, Debug)]
pub enum PromptError {
    #[error(transparent)]
    FernError(#[from] fern::InitError),
    #[error(transparent)]
    IOError(#[from] IOError),
    #[error(transparent)]
    ReaderError(#[from] TryRecvError),
    #[error("Poison Error: {}", _0)]
    PoisonError(String),
}

impl<T> From<PoisonError<T>> for PromptError {
    fn from(err: PoisonError<T>) -> Self {
        Self::PoisonError(format!("{}", err))
    }
}

pub struct Prompt {
    receiver: Mutex<Receiver<String>>,
    prompt: Mutex<Option<String>>,
    history: Mutex<Vec<String>>
}

impl Prompt {
    pub fn new(debug: bool, disable_file_logging: bool) -> Result<Arc<Self>, PromptError>  {
        let (sender, receiver) = channel();
        let v = Self {
            receiver: Mutex::new(receiver),
            prompt: Mutex::new(None),
            history: Mutex::new(Vec::new())
        };
        v.start_thread(sender);
        let prompt = Arc::new(v);
        prompt.clone().setup_logger(debug, disable_file_logging)?;
        Ok(prompt)
    }

    fn start_thread(&self, sender: Sender<String>) {
        debug!("Starting prompt thread");
        thread::spawn(move || {
            loop {
                let mut input = String::new();
                if let Err(e) = stdin().read_line(&mut input) {
                    error!("Error while reading input: {}", e);
                    return;
                }
                let input = input.trim().to_string();
                if input.len() > 0 {
                    if let Err(e) = sender.send(input) {
                        error!("Error while sending input: {}", e);
                        return;
                    }
                }
            }
        });
    }

    pub fn update_prompt(&self, prompt: Option<String>) -> Result<(), PromptError> {
        *self.prompt.lock()? = prompt;
        self.show()
    }

    pub fn read_command(&self) -> Result<Option<String>, PromptError> {
        match self.receiver.lock()?.try_recv() {
            Ok(cmd) => {
                self.history.lock()?.push(cmd.clone());
                Ok(Some(cmd))
            },
            Err(e) if e == TryRecvError::Empty => Ok(None),
            Err(e) => return Err(PromptError::ReaderError(e))
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