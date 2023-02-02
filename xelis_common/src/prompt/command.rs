use std::{collections::HashMap, pin::Pin, future::Future};

use crate::config::VERSION;

use super::argument::*;
use thiserror::Error;
use log::info;

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
    NoData
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
    optional_arg: Option<Arg>,
    callback: CommandHandler<T>
}

impl<T> Command<T> {
    pub fn new(name: &str, description: &str, optional_arg: Option<Arg>, callback: CommandHandler<T>) -> Self {
        Self {
            name: name.to_owned(),
            description: description.to_owned(),
            required_args: Vec::new(),
            optional_arg,
            callback
        }
    }

    pub fn with_required_arguments(name: &str, description: &str, required_args: Vec<Arg>, optional_arg: Option<Arg>, callback: CommandHandler<T>) -> Self {
        Self {
            name: name.to_owned(),
            description: description.to_owned(),
            required_args,
            optional_arg,
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

    pub fn get_optional_arg(&self) -> &Option<Arg> {
        &self.optional_arg
    }

    pub fn get_usage(&self) -> String {
        let required_args: Vec<String> = self.get_required_args().iter().map(|arg| format!("<{}>", arg.get_name())).collect();
        let optional_arg: String = match self.get_optional_arg() {
            Some(v) => format!("{}[{}]", if required_args.is_empty() { "" } else { " " }, v.get_name()),
            None => "".to_owned()
        };
        format!("{} {}{}", self.get_name(), required_args.join(" "), optional_arg)
    }
}

pub struct CommandManager<T> {
    commands: Vec<Command<T>>,
    data: Option<T>
}

impl<T> CommandManager<T> {
    pub fn new(data: Option<T>) -> Self {
        Self {
            commands: Vec::new(),
            data
        }
    }

    pub fn default() -> Self {
        let mut zelf = CommandManager::new(None);
        zelf.add_command(Command::new("help", "Show this help", Some(Arg::new("command", ArgType::String)), CommandHandler::Sync(help)));
        zelf.add_command(Command::new("version", "Show the current version", None, CommandHandler::Sync(version)));
        zelf.add_command(Command::new("exit", "Shutdown the daemon", None, CommandHandler::Sync(exit)));
        zelf
    }

    pub fn set_data(&mut self, data: Option<T>) {
        self.data = data;
    }

    pub fn get_data<'a>(&'a self) -> Result<&'a T, CommandError> {
        self.data.as_ref().ok_or(CommandError::NoData)
    }

    pub fn add_command(&mut self, command: Command<T>) {
        self.commands.push(command);
    }

    pub fn get_commands(&self) -> &Vec<Command<T>> {
        &self.commands
    }

    pub fn get_command(&self, name: &str) -> Option<&Command<T>> {
        self.commands.iter().find(|command| *command.get_name() == *name)
    }

    pub async fn handle_command(&self, value: String) -> Result<(), CommandError> {
        let mut command_split = value.split_whitespace();
        let command_name = command_split.next().ok_or(CommandError::ExpectedCommandName)?;
        let command = self.get_command(command_name).ok_or(CommandError::CommandNotFound)?;
        let mut arguments: HashMap<String, ArgValue> = HashMap::new();
        for arg in command.get_required_args() {
            let arg_value = command_split.next().ok_or_else(|| CommandError::ExpectedRequiredArg(arg.get_name().to_owned()))?;
            arguments.insert(arg.get_name().clone(), arg.get_type().to_value(arg_value)?);
        }

        if let Some(arg_value) = command_split.next() {
            if let Some(optional_arg) = command.get_optional_arg() {
                arguments.insert(optional_arg.get_name().clone(), optional_arg.get_type().to_value(arg_value)?);
            } else {
                return Err(CommandError::TooManyArguments);
            }
        }

        if command_split.next().is_some() {
            return Err(CommandError::TooManyArguments);
        }

        command.execute(self, ArgumentManager::new(arguments)).await
    }

    pub fn message(&self, message: &str) {
        info!("{}", message);
    }
}

fn help<T>(manager: &CommandManager<T>, mut args: ArgumentManager) -> Result<(), CommandError> {
    if args.has_argument("command") {
        let arg_value = args.get_value("command")?.to_string_value()?;
        let cmd = manager.get_command(&arg_value).ok_or(CommandError::CommandNotFound)?;
        manager.message(&format!("Usage: {}", cmd.get_usage()));
    } else {
        manager.message("Available commands:");
        for cmd in manager.get_commands() {
            manager.message(&format!("- {}: {}", cmd.get_name(), cmd.get_description()));
        }
    }
    Ok(())
}

fn exit<T>(_: &CommandManager<T>, _: ArgumentManager) -> Result<(), CommandError> {
    info!("Stopping...");
    Err(CommandError::Exit)
}

fn version<T>(_: &CommandManager<T>, _: ArgumentManager) -> Result<(), CommandError> {
    info!("Version: {}", VERSION);
    Ok(())
}