use std::borrow::Borrow;

use actix::{Actor, StreamHandler, AsyncContext, Message as TMessage, Handler, Addr};
use actix_web_actors::ws::{ProtocolError, Message, WebsocketContext};
use serde::Deserialize;
use serde_json::{Value, json};
use xelis_common::api::daemon::NotifyEvent;
use super::{SharedRpcServer, RpcError, RpcResponseError, JSON_RPC_VERSION};
use log::{debug, trace};

pub struct Response<T: Borrow<Value> + ToString>(pub T);

#[derive(Deserialize)]
pub struct SubscribeParams {
    notify: NotifyEvent
}

impl<T: Borrow<Value> + ToString> TMessage for Response<T> {
    type Result = Result<(), RpcError>;
}

pub struct WebSocketHandler {
    server: SharedRpcServer
}

impl Actor for WebSocketHandler {
    type Context = WebsocketContext<Self>;
}

impl StreamHandler<Result<Message, ProtocolError>> for WebSocketHandler {
    fn handle(&mut self, msg: Result<Message, ProtocolError>, ctx: &mut Self::Context) {
        match msg {
            Ok(Message::Text(text)) => {
                let address = ctx.address();
                let server = self.server.clone();
                let fut = async move {
                    let response = match WebSocketHandler::handle_request(&address, server, &text.as_bytes()).await {
                        Ok(result) => result,
                        Err(e) => e.to_json()
                    };
                    if let Err(e) = address.send(Response(response)).await {
                        debug!("Error while sending response to {:?}: {}", address, e);
                    }
                };
                let fut = actix::fut::wrap_future(fut);
                ctx.spawn(fut);
            },
            Ok(Message::Close(reason)) => {
                trace!("Received closing message, removing client");
                let server = self.server.clone();
                let address = ctx.address();
                let fut = async move {
                    server.remove_client(&address).await;
                };
                ctx.wait(actix::fut::wrap_future(fut));
                ctx.close(reason);
            },
            msg => {
                debug!("Abnormal message received: {:?}. Closing connection", msg);
                let error = RpcResponseError::new(None, RpcError::InvalidRequest);
                ctx.text(error.to_json().to_string());
                ctx.close(None);
            }
        }
    }

    fn finished(&mut self, ctx: &mut Self::Context) {
        trace!("Websocket handler is finished, removing client");
        let server = self.server.clone();
        let address = ctx.address();
        let fut = async move {
            server.remove_client(&address).await;
        };
        ctx.wait(actix::fut::wrap_future(fut));
    }
}

impl<T: Borrow<Value> + ToString> Handler<Response<T>> for WebSocketHandler {
    type Result = Result<(), RpcError>;

    fn handle(&mut self, msg: Response<T>, ctx: &mut Self::Context) -> Self::Result {
        ctx.text(msg.0.to_string());
        Ok(())
    }
}

impl WebSocketHandler {
    pub fn new(server: SharedRpcServer) -> Self {
        Self {
            server
        }
    }

    pub async fn handle_request(addr: &Addr<WebSocketHandler>, server: SharedRpcServer, body: &[u8]) -> Result<Value, RpcResponseError> {
        let mut request = server.parse_request(body)?;
        let method = request.method.as_str(); 
        match method {
            "subscribe" | "unsubscribe" => {
                let params: SubscribeParams = serde_json::from_value(request.params.take().unwrap_or(Value::Null)).map_err(|e| RpcResponseError::new(request.id, RpcError::InvalidParams(e)))?;
                let res = if method == "subscribe" {
                    server.subscribe_client_to(addr, params.notify, request.id).await
                } else {
                    server.unsubscribe_client_from(addr, &params.notify).await
                };
                res.map_err(|e| RpcResponseError::new(request.id, e))?;

                Ok(json!({
                    "jsonrpc": JSON_RPC_VERSION,
                    "id": request.id,
                    "result": json!(true)
                }))
            },
            _ => server.execute_method(request).await
        }
    }
}