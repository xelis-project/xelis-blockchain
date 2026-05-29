use std::fmt::{Display, Formatter};


use serde_json::{Value, Error as SerdeError, json};
use thiserror::Error;
use anyhow::Error as AnyError;
use crate::{error::ErrorWithKind, rpc::{Id, JSON_RPC_VERSION}};

#[cfg(feature = "rpc-client")]
use super::client::JsonRPCError;

#[cfg(feature = "rpc-server")]
use actix_web::{ResponseError, HttpResponse};

/// Trait for RPC errors that can be converted into an `AnyError` and have a kind string.
pub trait RPCError: Into<AnyError> {
    fn kind(&self) -> &'static str;
}

impl<T: RPCError> From<T> for ErrorWithKind {
    fn from(value: T) -> Self {
        Self {
            kind: value.kind(),
            error: value.into()
        }
    }
}

impl From<ErrorWithKind> for InternalRpcError {
    fn from(value: ErrorWithKind) -> Self {
        Self::Any {
            kind: value.kind,
            error: value.error
        }
    }
}

#[derive(Error, Debug)]
pub enum InternalRpcError {
    #[error("Internal error: {}", _0)]
    InternalError(&'static str),
    #[error("Invalid context")]
    InvalidContext,
    #[error("Invalid body in request")]
    ParseBodyError,
    #[error("Invalid JSON request")]
    InvalidJSONRequest,
    #[error("Invalid request: {}", _0)]
    InvalidRequestStr(&'static str),
    #[error("Invalid params: {}", _0)]
    InvalidJSONParams(#[from] SerdeError),
    #[error("Invalid params: {}", _0)]
    InvalidParams(&'static str),
    #[error("Invalid params: {:#}", _0)]
    InvalidParamsAny(AnyError),
    #[error("Expected parameters for this method but was not present")]
    ExpectedParams,
    #[error("Unexpected parameters for this method")]
    UnexpectedParams,
    #[error("Expected json_rpc set to '2.0'")]
    InvalidVersion,
    #[error("Method '{}' in request was not found", _0)]
    MethodNotFound(String),
    #[error("{error:#}")]
    Any {
        kind: &'static str,
        error: AnyError
    },
    #[error("Websocket client was not found")]
    ClientNotFound,
    #[error("Event is not subscribed")]
    EventNotSubscribed,
    #[error("Event is already subscribed")]
    EventAlreadySubscribed,
    #[error("batch limit exceeded")]
    BatchLimitExceeded,
}

impl From<AnyError> for InternalRpcError {
    fn from(value: AnyError) -> Self {
        Self::Any {
            kind: "UNSPECIFIED",
            error: value
        }
    }
}

impl InternalRpcError {
    pub fn get_code(&self) -> i16 {
        match self {
            // JSON RPC errors
            Self::ParseBodyError => -32700,
            Self::InvalidJSONRequest
            | Self::InvalidRequestStr(_)
            | Self::InvalidVersion
            | Self::BatchLimitExceeded => -32600,
            Self::MethodNotFound(_) => -32601,
            Self::InvalidJSONParams(_)
            | Self::InvalidParams(_)
            | Self::InvalidParamsAny(_)
            | Self::UnexpectedParams
            | Self::ExpectedParams => -32602,
            // Internal errors
            Self::InternalError(_) => -32603,
            // 32000 to -32099	Server error (Reserved for implementation-defined server-errors)
            Self::InvalidContext => -32001,
            Self::ClientNotFound => -32002,
            Self::Any { .. } => -32004,
            // Events invalid requests
            Self::EventNotSubscribed => -1,
            Self::EventAlreadySubscribed => -2,
        }
    }

    pub const fn get_kind(&self) -> &'static str {
        match self {
            Self::ParseBodyError => "BODY_ERROR",
            Self::InvalidJSONRequest => "INVALID_JSON_REQUEST",
            Self::InvalidRequestStr(_) => "INVALID_REQUEST",
            Self::InvalidParams(_) | Self::InvalidJSONParams(_) | Self::InvalidParamsAny(_) => "INVALID_PARAMS",
            Self::UnexpectedParams => "UNEXPECTED_PARAMS",
            Self::ExpectedParams => "EXPECTED_PARAMS",
            Self::InvalidVersion => "INVALID_VERSION",
            Self::MethodNotFound(_) => "METHOD_NOT_FOUND",
            Self::InternalError(_) => "INTERNAL_ERROR",
            Self::InvalidContext => "INVALID_CONTEXT",
            Self::ClientNotFound => "CLIENT_NOT_FOUND",
            Self::Any { kind, .. } => kind,
            Self::EventNotSubscribed => "EVENT_NOT_SUBSCRIBED",
            Self::EventAlreadySubscribed => "EVENT_ALREADY_SUBSCRIBED",
            Self::BatchLimitExceeded => "BATCH_LIMIT_EXCEEDED",
        }
    }
}

#[derive(Debug)]
pub struct RpcResponseError {
    id: Option<Id>,
    error: InternalRpcError
}

impl RpcResponseError {
    pub fn new<T: Into<InternalRpcError>>(id: Option<Id>, error: T) -> Self {
        Self {
            id,
            error: error.into()
        }
    }

    pub fn get_id(&self) -> Value {
        match &self.id {
            Some(id) => json!(id),
            None => Value::Null
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "jsonrpc": JSON_RPC_VERSION,
            "id": self.get_id(),
            "error": {
                "code": self.error.get_code(),
                "kind": self.error.get_kind(),
                "message": format!("{:#}", self.error)
            }
        })
    }
}

impl Display for RpcResponseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "RpcError[id: {}, error: {:#}]", self.get_id(), self.error)
    }
}

#[cfg(feature = "rpc-server")]
impl ResponseError for RpcResponseError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::Ok().json(self.to_json())
    }
}

#[cfg(feature = "rpc-client")]
impl From<JsonRPCError> for InternalRpcError {
    fn from(value: JsonRPCError) -> Self {
        Self::Any {
            kind: (&value).into(),
            error: value.into(),
        }
    }
}
