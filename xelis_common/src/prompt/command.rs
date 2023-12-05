use std::{collections::HashMap, pin::Pin, future::Future, fmt::Display, time::{Instant, Duration}, sync::{Mutex, PoisonError}, rc::Rc};

use crate::{config::VERSION, async_handler};

use super::{argument::*, ShareablePrompt};
use anyhow::Error;
use thiserror::Error;
use log::{info, warn, error};

#[derive(Error, Debug)]
pub enum CommandError {
    #[error("Expected a command name")]
    ExpectedCommandName,
    #[error("Command was not found")]
    CommandNotFound,
    #[error("Expected required argument {}", _0)]
    ExpectedRequiredArg(String), // arg name
    #[error("Too many arguments")]
    TooManyArguments,
    #[error(transparent)]
    ArgError(#[from] ArgError),
    #[error("Invalid argument: {}", _0)]
    InvalidArgument(String),
    #[error("Exit command was called")]
    Exit,
    #[error("No data was set in command manager")]
    NoData,
    #[error("No prompt was set in command manager")]
    NoPrompt,
    #[error(transparent)]
    Any(#[from] Error),
    #[error("Poison Error: {}", _0)]
    PoisonError(String)
}

impl<T> From<PoisonError<T>> for CommandError {
    fn from(err: PoisonError<T>) -> Self {
        Self::PoisonError(format!("{}", err))
    }
}

pub type SyncCommandCallback<T> = fn(&CommandManager<T>, ArgumentManager) -> Result<(), CommandError>;
pub type AsyncCommandCallback<T> = fn(&'_ CommandManager<T>, ArgumentManager) -> Pin<Box<dyn Future<Output = Result<(), CommandError>> + '_>>;

pub enum CommandHandler<T> {
    Sync(SyncCommandCallback<T>),
    Async(AsyncCommandCallback<T>)
}

pub struct Command<T> {
    name: String,
    description: String,
    required_args: Vec<Arg>,
    optional_args: Vec<Arg>,
    callback: CommandHandler<T>
}

impl<T> Command<T> {
    pub fn new(name: &str, description: &str, callback: CommandHandler<T>) -> Self {
        Self {
            name: name.to_owned(),
            description: description.to_owned(),
            required_args: Vec::new(),
            optional_args: Vec::new(),
            callback
        }
    }

    pub fn with_optional_arguments(name: &str, description: &str, optional_args: Vec<Arg>, callback: CommandHandler<T>) -> Self {
        Self {
            name: name.to_owned(),
            description: description.to_owned(),
            required_args: Vec::new(),
            optional_args,
            callback
        }
    }

    pub fn with_required_arguments(name: &str, description: &str, required_args: Vec<Arg>, callback: CommandHandler<T>) -> Self {
        Self {
            name: name.to_owned(),
            description: description.to_owned(),
            required_args,
            optional_args: Vec::new(),
            callback
        }
    }

    pub fn with_arguments(name: &str, description: &str, required_args: Vec<Arg>, optional_args: Vec<Arg>, callback: CommandHandler<T>) -> Self {
        Self {
            name: name.to_owned(),
            description: description.to_owned(),
            required_args,
            optional_args,
            callback
        }
    }

    pub async fn execute(&self, manager: &CommandManager<T>, values: ArgumentManager) -> Result<(), CommandError> {
        match &self.callback {
            CommandHandler::Sync(handler) => {
                handler(manager, values)
            },
            CommandHandler::Async(handler) => {
                handler(manager, values).await
            },
        }
    }

    pub fn get_name(&self) -> &String {
        &self.name
    }

    pub fn get_description(&self) -> &String {
        &self.description
    }

    pub fn get_required_args(&self) -> &Vec<Arg> {
        &self.required_args
    }

    pub fn get_optional_args(&self) -> &Vec<Arg> {
        &self.optional_args
    }

    pub fn get_usage(&self) -> String {
        let required_args: Vec<String> = self.get_required_args()
            .iter()
            .map(|arg| format!("<{}>", arg.get_name()))
            .collect();

        let optional_args: Vec<String> = self.get_optional_args()
            .iter()
            .map(|arg| format!("[{}]", arg.get_name()))
            .collect();

        format!("{} {}{}", self.get_name(), required_args.join(" "), optional_args.join(" "))
    }
}

// We use Mutex from std instead of tokio so we can use it in sync code too
pub struct CommandManager<T> {
    commands: Mutex<Vec<Rc<Command<T>>>>,
    data: Mutex<Option<T>>,
    prompt: ShareablePrompt,
    running_since: Instant
}

impl<T> CommandManager<T> {
    pub fn new(data: Option<T>, prompt: ShareablePrompt) -> Self {
        Self {
            commands: Mutex::new(Vec::new()),
            data: Mutex::new(data),
            prompt,
            running_since: Instant::now()
        }
    }

    pub fn default(prompt: ShareablePrompt) -> Result<Self, CommandError> {
        let zelf = CommandManager::new(None, prompt);
        zelf.add_command(Command::with_optional_arguments("help", "Show this help", vec![Arg::new("command", ArgType::String)], CommandHandler::Async(async_handler!(help))))?;
        zelf.add_command(Command::new("version", "Show the current version", CommandHandler::Sync(version)))?;
        zelf.add_command(Command::new("exit", "Shutdown the daemon", CommandHandler::Sync(exit)))?;
        Ok(zelf)
    }

    pub fn set_data(&self, data: Option<T>) -> Result<(), CommandError> {
        *self.data.lock()? = data;
        Ok(())
    }

    pub fn get_data<'a>(&'a self) -> &Mutex<Option<T>> {
        &self.data
    }

    pub fn get_prompt<'a>(&'a self) -> &ShareablePrompt {
        &self.prompt
    }

    pub fn add_command(&self, command: Command<T>) -> Result<(), CommandError> {
        let mut commands = self.commands.lock()?;
        commands.push(Rc::new(command));
        Ok(())
    }

    pub fn get_commands(&self) -> &Mutex<Vec<Rc<Command<T>>>> {
        &self.commands
    }

    pub async fn handle_command(&self, value: String) -> Result<(), CommandError> {
        let mut command_split = value.split_whitespace();
        let command_name = command_split.next().ok_or(CommandError::ExpectedCommandName)?;
        let command = {
            let commands = self.commands.lock()?;
            commands.iter().find(|command| *command.get_name() == *command_name).cloned().ok_or(CommandError::CommandNotFound)?
        };
        let mut arguments: HashMap<String, ArgValue> = HashMap::new();
        for arg in command.get_required_args() {
            let arg_value = command_split.next().ok_or_else(|| CommandError::ExpectedRequiredArg(arg.get_name().to_owned()))?;
            arguments.insert(arg.get_name().clone(), arg.get_type().to_value(arg_value)?);
        }

        // include all options args available
        for optional_arg in command.get_optional_args() {
            if let Some(arg_value) = command_split.next() {
                arguments.insert(optional_arg.get_name().clone(), optional_arg.get_type().to_value(arg_value)?);
            } else {
                break;
            }
        }

        if command_split.next().is_some() {
            return Err(CommandError::TooManyArguments);
        }

        command.execute(self, ArgumentManager::new(arguments)).await
    }

    pub fn display_commands(&self) -> Result<(), CommandError> {
        let commands = self.commands.lock()?;
        self.message("Available commands:");
        for cmd in commands.iter() {
            self.message(format!("- {}: {}", cmd.get_name(), cmd.get_description()));
        }
        Ok(())
    }

    pub fn message<D: Display>(&self, message: D) {
        info!("{}", message);
    }

    pub fn warn<D: Display>(&self, message: D) {
        warn!("{}", message);
    }

    pub fn error<D: Display>(&self, message: D) {
        error!("{}", message);
    }

    pub fn running_since(&self) -> Duration {
        self.running_since.elapsed()
    }
}

async fn help<T>(manager: &CommandManager<T>, mut args: ArgumentManager) -> Result<(), CommandError> {
    if args.has_argument("command") {
        let arg_value = args.get_value("command")?.to_string_value()?;
        let commands = manager.get_commands().lock()?;
        let cmd = commands.iter().find(|command| *command.get_name() == *arg_value).ok_or(CommandError::CommandNotFound)?;
        manager.message(&format!("Usage: {}", cmd.get_usage()));
    } else {
        manager.display_commands()?;
        manager.message("See how to use a command using /help <command>");
    }
    Ok(())
}

fn exit<T>(manager: &CommandManager<T>, _: ArgumentManager) -> Result<(), CommandError> {
    manager.message("Stopping...");
    Err(CommandError::Exit)
}

fn version<T>(manager: &CommandManager<T>, _: ArgumentManager) -> Result<(), CommandError> {
    manager.message(format!("Version: {}", VERSION));
    Ok(())
}