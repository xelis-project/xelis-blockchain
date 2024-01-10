use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;
use tokio_tungstenite::tungstenite::Error as TungsteniteError;

mod http;
mod websocket;

pub use http::JsonRPCClient;
pub use websocket::{WebSocketJsonRPCClientImpl, WebSocketJsonRPCClient, EventReceiver};

const JSON_RPC_VERSION: &str = "2.0";

const PARSE_ERROR_CODE: i16 = -32700;
const INVALID_REQUEST_CODE: i16 = -32600;
const METHOD_NOT_FOUND_CODE: i16 = -32601;
const INVALID_PARAMS_CODE: i16 = -32602;
const INTERNAL_ERROR_CODE: i16 = -32603;

pub type JsonRPCResult<T> = Result<T, JsonRPCError>;

#[derive(Debug, Deserialize)]
struct JsonRPCResponse {
    id: Option<usize>,
    result: Option<Value>,
    error: Option<JsonRPCErrorResponse>,
}

#[derive(Debug, Deserialize)]
struct JsonRPCErrorResponse {
    code: i16,
    message: String,
    #[serde(default)]
    data: Option<Value>,
}

#[derive(Debug, Error)]
pub enum JsonRPCError {
    #[error("Server failed to parse request JSON data")]
    ParseError,
    #[error("Server received invalid JSON-RPC request")]
    InvalidRequest,
    #[error("Unknown method requested to the server")]
    MethodNotFound,
    #[error("Invalid parameters were provided")]
    InvalidParams,
    #[error("Server internal JSON-RPC error: {}", message)]
    InternalError {
        message: String,
        data: Option<String>,
    },
    #[error("Server returned error: [{}] {}", code, message)]
    ServerError {
        code: i16,
        message: String,
        data: Option<String>,
    },
    #[error("Server did not respond to the request")]
    NoResponse,
    #[error("Server returned a response without result")]
    MissingResult,
    #[error("Error while (de)serializing JSON data: {}", _0)]
    SerializationError(#[from] serde_json::Error),
    #[error("HTTP error during JSON-RPC communication: {}", _0)]
    HttpError(#[from] reqwest::Error),
    #[error("Error during JSON-RPC communication: {}", _0)]
    ConnectionError(String),
    #[error("Event not registered")]
    EventNotRegistered,
    #[error(transparent)]
    SocketError(#[from] TungsteniteError),
    #[error(transparent)]
    Any(#[from] anyhow::Error)
}