use std::{fmt, ops::Deref};

use anyhow::Error as AnyError;

/// A wrapper for any error that includes a kind string for easier serialization in RPC responses.
#[derive(Debug)]
pub struct ErrorWithKind {
    pub kind: &'static str,
    pub error: AnyError
}

impl fmt::Display for ErrorWithKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl Deref for ErrorWithKind {
    type Target = AnyError;

    fn deref(&self) -> &Self::Target {
        &self.error
    }
}

impl From<AnyError> for ErrorWithKind {
    fn from(value: AnyError) -> Self {
        Self {
            kind: "UNSPECIFIED",
            error: value
        }
    }
}

impl From<ErrorWithKind> for AnyError {
    fn from(value: ErrorWithKind) -> Self {
        value.error
    }
}
