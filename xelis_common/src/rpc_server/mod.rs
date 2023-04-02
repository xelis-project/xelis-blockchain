pub mod websocket;
mod error;
mod rpc_handler;

pub use error::{RpcResponseError, InternalRpcError};
pub use rpc_handler::{RPCHandler, Handler};

use actix_web::{HttpResponse, web::{self, Data, Payload}, Responder, HttpRequest};
use serde::Deserialize;
use serde_json::Value;

use self::websocket::{WebSocketServerShared, WebSocketHandler};

pub const JSON_RPC_VERSION: &str = "2.0";

#[derive(Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub id: Option<usize>,
    pub method: String,
    pub params: Option<Value>
}

// trait to retrieve easily a JSON RPC handler for registered route
pub trait RPCServerHandler<T: Sync + Send + Clone + 'static> {
    fn get_rpc_handler(&self) -> &RPCHandler<T>;
}

// JSON RPC handler endpoint
pub async fn json_rpc<T, H>(server: Data<H>, body: web::Bytes) -> Result<impl Responder, RpcResponseError>
where
    T: Clone + Send + Sync + 'static,
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
    let response = server.get_websocket().handle_connection(&request, body).await?;
    Ok(response)
}