use std::fmt::{Display, Formatter};
use actix_web::{ResponseError, HttpResponse};
use serde_json::{Value, Error as SerdeError, json};
use thiserror::Error;
use anyhow::Error as AnyError;
use crate::{serializer::ReaderError, rpc_server::JSON_RPC_VERSION};

#[derive(Error, Debug)]
pub enum InternalRpcError {
    #[error("Invalid context")]
    InvalidContext,
    #[error("Invalid body in request")]
    ParseBodyError,
    #[error("Invalid request")]
    InvalidRequest,
    #[error("Invalid params: {}", _0)]
    InvalidParams(#[from] SerdeError),
    #[error("Expected parameters for this method but was not present")]
    ExpectedParams,
    #[error("Unexpected parameters for this method")]
    UnexpectedParams,
    #[error("Expected json_rpc set to '2.0'")]
    InvalidVersion,
    #[error("Method '{}' in request was not found", _0)]
    MethodNotFound(String),
    #[error(transparent)]
    DeserializerError(#[from] ReaderError),
    #[error(transparent)]
    AnyError(#[from] AnyError),
    #[error("Websocket client was not found")]
    ClientNotFound,
    #[error("Event is not subscribed")]
    EventNotSubscribed,
    #[error("Event is already subscribed")]
    EventAlreadySubscribed,
    #[error("{}", _0)]
    Custom(String),
    #[error("{}", _0)]
    CustomStr(&'static str)
}

impl InternalRpcError {
    pub fn get_code(&self) -> i16 {
        match self {
            Self::ParseBodyError => -32700,
            Self::InvalidRequest | InternalRpcError::InvalidVersion => -32600,
            Self::MethodNotFound(_) => -32601,
            Self::InvalidParams(_) | InternalRpcError::UnexpectedParams => -32602,
            _ => -32603
        }
    }
}

#[derive(Debug)]
pub struct RpcResponseError {
    id: Option<usize>,
    error: InternalRpcError
}

impl RpcResponseError {
    pub fn new(id: Option<usize>, error: InternalRpcError) -> Self {
        Self {
            id,
            error
        }
    }

    pub fn get_id(&self) -> Value {
        match self.id {
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
                "message": self.error.to_string()
            }
        })
    }
}

impl Display for RpcResponseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "RpcError[id: {}, error: {}]", self.get_id(), self.error.to_string())
    }
}

impl ResponseError for RpcResponseError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::Ok().json(self.to_json())
    }
}

