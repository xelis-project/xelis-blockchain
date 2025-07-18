use std::{
    sync::PoisonError,
    io::Error as IOError
};

use anyhow::Error;
use thiserror::Error;

use crate::serializer::ReaderError;
use super::command::CommandError;

#[derive(Error, Debug)]
pub enum PromptError {
    #[error("Logs path is not a folder, it must ends with /")]
    LogsPathNotFolder,
    #[error("Filename for log cannot be a directory")]
    FileNotDir,
    #[error("Auto compress logs is enabled but date based logs are disabled")]
    AutoCompressParam,
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
    #[error(transparent)]
    Any(#[from] Error)
}

impl<T> From<PoisonError<T>> for PromptError {
    fn from(err: PoisonError<T>) -> Self {
        Self::PoisonError(format!("{}", err))
    }
}

impl From<PromptError> for CommandError {
    fn from(err: PromptError) -> Self {
        Self::Any(err.into())
    }
}
