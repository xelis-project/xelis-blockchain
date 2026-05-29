pub mod websocket;

use actix_web::{
    HttpResponse,
    web::{self, Data, Payload},
    Responder,
    HttpRequest
};
use runtime_context::ShareableTid;

use super::{RPCHandler, RpcResponseError};
use self::websocket::{WebSocketServerShared, WebSocketHandler};

// trait to retrieve easily a JSON RPC handler for registered route
pub trait RPCServerHandler<T: ShareableTid<'static>> {
    fn get_rpc_handler(&self) -> &RPCHandler<T>;
}

// JSON RPC handler endpoint
pub async fn json_rpc<T, H>(server: Data<H>, body: web::Bytes) -> Result<impl Responder, RpcResponseError>
where
    T: ShareableTid<'static>,
    H: RPCServerHandler<T>
{
    match server.get_rpc_handler().handle_request(&body).await? {
        Some(result) => Ok(HttpResponse::Ok().json(result)),
        None => Ok(HttpResponse::Ok().finish()),
    }
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