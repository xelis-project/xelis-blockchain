use std::collections::HashMap;

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
    InvalidArgument(String)
}

pub type CommandCallback = fn(&CommandManager, ArgumentManager) -> Result<(), CommandError>;

pub struct Command {
    name: String,
    description: String,
    required_args: Vec<Arg>,
    optional_arg: Option<Arg>,
    callback: CommandCallback
}

impl Command {
    pub fn new(name: &str, description: &str, optional_arg: Option<Arg>, callback: CommandCallback) -> Self {
        Self {
            name: name.to_owned(),
            description: description.to_owned(),
            required_args: Vec::new(),
            optional_arg,
            callback
        }
    }

    pub fn with_required_arguments(name: &str, description: &str, required_args: Vec<Arg>, optional_arg: Option<Arg>, callback: CommandCallback) -> Self {
        Self {
            name: name.to_owned(),
            description: description.to_owned(),
            required_args,
            optional_arg,
            callback
        }
    }

    pub fn execute(&self, manager: &CommandManager, values: ArgumentManager) -> Result<(), CommandError> {
        (self.callback)(manager, values)
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

pub struct CommandManager {
    commands: Vec<Command>
}

impl CommandManager {
    pub fn new() -> Self {
        Self {
            commands: Vec::new()
        }
    }

    pub fn add_command(&mut self, command: Command) {
        self.commands.push(command);
    }

    pub fn get_commands(&self) -> &Vec<Command> {
        &self.commands
    }

    pub fn get_command(&self, name: &str) -> Option<&Command> {
        self.commands.iter().find(|command| *command.get_name() == *name)
    }

    pub fn handle_command(&self, value: String) -> Result<(), CommandError> {
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

        command.execute(self, ArgumentManager::new(arguments))
    }

    pub fn message(&self, message: &str) {
        info!("{}", message);
    }
}