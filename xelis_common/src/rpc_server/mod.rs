pub mod websocket;
mod error;
mod rpc_handler;

use std::borrow::Cow;

pub use error::{RpcResponseError, InternalRpcError};
pub use rpc_handler::{RPCHandler, Handler};
pub use rpc_handler::parse_params;

use actix_web::{HttpResponse, web::{self, Data, Payload}, Responder, HttpRequest};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use self::websocket::{WebSocketServerShared, WebSocketHandler};

pub const JSON_RPC_VERSION: &str = "2.0";

#[derive(Clone, Serialize, Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub id: Option<usize>,
    pub method: String,
    pub params: Option<Value>
}

#[derive(Serialize)]
pub struct RpcResponse<'a> {
    pub jsonrpc: &'a str,
    pub id: Cow<'a, Option<usize>>,
    pub result: Cow<'a, Value>
}

impl<'a> RpcResponse<'a> {
    pub fn new(id: Cow<'a, Option<usize>>, result: Cow<'a, Value>) -> Self {
        Self {
            jsonrpc: JSON_RPC_VERSION,
            id,
            result
        }
    }
}

// trait to retrieve easily a JSON RPC handler for registered route
pub trait RPCServerHandler<T: Send + Clone> {
    fn get_rpc_handler(&self) -> &RPCHandler<T>;
}

// JSON RPC handler endpoint
pub async fn json_rpc<T, H>(server: Data<H>, body: web::Bytes) -> Result<impl Responder, RpcResponseError>
where
    T: Send + Sync + Clone + 'static,
    H: RPCServerHandler<T>
{
    let result = server.get_rpc_handler().handle_request(&body).await?;
    Ok(HttpResponse::Ok().json(result))
}

// trait to retrieve easily a websocket handler for registered route
pub trait WebSocketServerHandler<H: WebSocketHandler> {
    fn get_websocket(&self) -> &WebSocketServerShared<H>;
}

// WebSocket JSON RPC handler endpoint
pub async fn websocket<H, S>(server: Data<S>, request: HttpRequest, body: Payload) -> Result<impl Responder, actix_web::Error>
where
    H: WebSocketHandler + 'static,
    S: WebSocketServerHandler<H>
{
    let response = server.get_websocket().handle_connection(request, body).await?;
    Ok(response)
}