use std::borrow::Cow;

use serde::{Deserialize, Serialize, de, ser::{self, SerializeStruct}};
use schemars::{JsonSchema, Schema, SchemaGenerator};
use thiserror::Error;
use xelis_vm::{EnvironmentError, VMError};

use crate::serializer::*;

// ExitError is a mirror to VMError without the embed error types
// this allows us to serialize it properly for RPC responses
// It should be serialized in the following format:
// { "code": "ILLEGAL_STATE", "message": "illegal state" }
#[derive(Debug, Clone, Error)]
pub enum ExitError {
    #[error("returned entry payload is invalid")]
    InvalidEntryPayloadReturn,
    #[error("unknown hook")]
    UnknownHook,
    #[error("invalid entry")]
    InvalidEntry,
    #[error("missing entry exit code")]
    MissingEntryExitCode,
    #[error("illegal state")]
    IllegalState,
    #[error("division by zero")]
    DivisionByZero,
    #[error("Assertion failed")]
    AssertionFailed,
    #[error("Out of bounds")]
    OutOfBounds,
    #[error("out of memory")]
    OutOfMemory,
    #[error("Not enough gas to complete the execution")]
    NotEnoughGas,
    #[error("Gas overflow")]
    GasOverflow,
    #[error("{0}")]
    RuntimeError(Cow<'static, str>),
}

impl ExitError {
    pub fn code(&self) -> &'static str {
        match self {
            ExitError::InvalidEntryPayloadReturn => "INVALID_ENTRY_PAYLOAD_RETURN",
            ExitError::UnknownHook => "UNKNOWN_HOOK",
            ExitError::InvalidEntry => "INVALID_ENTRY",
            ExitError::MissingEntryExitCode => "MISSING_ENTRY_EXIT_CODE",
            ExitError::IllegalState => "ILLEGAL_STATE",
            ExitError::DivisionByZero => "DIVISION_BY_ZERO",
            ExitError::AssertionFailed => "ASSERTION_FAILED",
            ExitError::OutOfBounds => "OUT_OF_BOUNDS",
            ExitError::OutOfMemory => "OUT_OF_MEMORY",
            ExitError::NotEnoughGas => "NOT_ENOUGH_GAS",
            ExitError::GasOverflow => "GAS_OVERFLOW",
            ExitError::RuntimeError(_) => "RUNTIME_ERROR",
        }
    }
}

impl Serializer for ExitError {
    fn write(&self, writer: &mut Writer) {
        match self {
            ExitError::InvalidEntryPayloadReturn => writer.write_u8(0),
            ExitError::UnknownHook => writer.write_u8(1),
            ExitError::InvalidEntry => writer.write_u8(2),
            ExitError::MissingEntryExitCode => writer.write_u8(3),
            ExitError::IllegalState => writer.write_u8(4),
            ExitError::DivisionByZero => writer.write_u8(5),
            ExitError::AssertionFailed => writer.write_u8(6),
            ExitError::OutOfBounds => writer.write_u8(7),
            ExitError::OutOfMemory => writer.write_u8(8),
            ExitError::NotEnoughGas => writer.write_u8(9),
            ExitError::GasOverflow => writer.write_u8(10),
            ExitError::RuntimeError(msg) => {
                writer.write_u8(11);
                msg.write(writer);
            }
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(match reader.read_u8()? {
            0 => ExitError::InvalidEntryPayloadReturn,
            1 => ExitError::UnknownHook,
            2 => ExitError::InvalidEntry,
            3 => ExitError::MissingEntryExitCode,
            4 => ExitError::IllegalState,
            5 => ExitError::DivisionByZero,
            6 => ExitError::AssertionFailed,
            7 => ExitError::OutOfBounds,
            8 => ExitError::OutOfMemory,
            9 => ExitError::NotEnoughGas,
            10 => ExitError::GasOverflow,
            11 => {
                let msg = Cow::Owned(String::read(reader)?);
                ExitError::RuntimeError(msg)
            }
            _ => return Err(ReaderError::InvalidValue),
        })
    }

    fn size(&self) -> usize {
        match self {
            ExitError::RuntimeError(msg) => 1 + msg.size(),
            _ => 1,
        }
    }
}

impl JsonSchema for ExitError {
    fn schema_name() -> Cow<'static, str> { Cow::from("ExitError") }

    fn json_schema(gen: &mut SchemaGenerator) -> Schema {
        #[derive(Serialize, Deserialize, JsonSchema)]
        #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
        enum ExitErrorCodeSchema {
            InvalidEntryPayloadReturn,
            UnknownHook,
            InvalidEntry,
            MissingEntryExitCode,
            IllegalState,
            DivisionByZero,
            AssertionFailed,
            OutOfBounds,
            OutOfMemory,
            NotEnoughGas,
            GasOverflow,
            RuntimeError,
        }

        #[derive(Serialize, Deserialize, JsonSchema)]
        struct ExitErrorWireSchema {
            code: ExitErrorCodeSchema,
            message: String,
        }

        gen.subschema_for::<ExitErrorWireSchema>()
    }
}

impl Serialize for ExitError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        let mut state = serializer.serialize_struct("ExitError", 2)?;
        state.serialize_field("code", self.code())?;
        state.serialize_field("message", &self.to_string())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for ExitError {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct ExitErrorHelper {
            code: String,
            message: String,
        }

        let helper = ExitErrorHelper::deserialize(deserializer)?;
        match helper.code.as_str() {
            "INVALID_ENTRY_PAYLOAD_RETURN" => Ok(ExitError::InvalidEntryPayloadReturn),
            "UNKNOWN_HOOK" => Ok(ExitError::UnknownHook),
            "INVALID_ENTRY" => Ok(ExitError::InvalidEntry),
            "MISSING_ENTRY_EXIT_CODE" => Ok(ExitError::MissingEntryExitCode),
            "ILLEGAL_STATE" => Ok(ExitError::IllegalState),
            "DIVISION_BY_ZERO" => Ok(ExitError::DivisionByZero),
            "ASSERTION_FAILED" => Ok(ExitError::AssertionFailed),
            "OUT_OF_BOUNDS" => Ok(ExitError::OutOfBounds),
            "OUT_OF_MEMORY" => Ok(ExitError::OutOfMemory),
            "NOT_ENOUGH_GAS" => Ok(ExitError::NotEnoughGas),
            "GAS_OVERFLOW" => Ok(ExitError::GasOverflow),
            "RUNTIME_ERROR" => Ok(ExitError::RuntimeError(helper.message.into())),
            _ => Err(de::Error::custom("Unknown ExitError code")),
        }
    }
}

// Safely create a runtime error with a message truncated to 255 characters
pub fn runtime_error(msg: impl Into<Cow<'static, str>>) -> ExitError {
    let mut msg = msg.into();
    if msg.len() > 255 {
        msg.to_mut().truncate(255);
    }

    ExitError::RuntimeError(msg.into())
}

impl From<EnvironmentError> for ExitError {
    fn from(err: EnvironmentError) -> Self {
        match err {
            EnvironmentError::OutOfMemory => ExitError::OutOfMemory,
            EnvironmentError::AssertionFailed => ExitError::AssertionFailed,
            EnvironmentError::NotEnoughGas { .. } => ExitError::NotEnoughGas,
            EnvironmentError::GasOverflow => ExitError::GasOverflow,
            EnvironmentError::DivisionByZero => ExitError::DivisionByZero,
            EnvironmentError::Static(msg) => runtime_error(msg),
            EnvironmentError::OutOfBounds(_, _) => ExitError::OutOfBounds,
            EnvironmentError::Expect(msg) => runtime_error(msg),
            _ => ExitError::IllegalState,
        }
    }
}

impl From<VMError> for ExitError {
    fn from(err: VMError) -> Self {
        match err {
            VMError::DivisionByZero => ExitError::DivisionByZero,
            VMError::EnvironmentError(err) => ExitError::from(err),
            VMError::OutOfMemory => ExitError::OutOfMemory,
            VMError::Any(err) => runtime_error(err.to_string()),
            _ => ExitError::IllegalState,
        }
    }
}
