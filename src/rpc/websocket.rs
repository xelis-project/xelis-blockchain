use actix::{Actor, StreamHandler, AsyncContext, Message as TMessage, Handler, ActorContext, Addr};
use actix_web_actors::ws::{ProtocolError, Message, WebsocketContext};
use serde::Deserialize;
use serde_json::Value;
use super::{SharedRpcServer, RpcError, RpcResponseError};
use log::debug;

struct Response(Value);

#[derive(Deserialize)]
pub struct SubscribeParams {
    notify: NotifyEvent
}

#[derive(PartialEq, Eq, Hash, Deserialize)]
pub enum NotifyEvent {
    // When a new block is accepted by chain
    NewBlock,
    // When a new transaction is added in mempool
    TransactionAddedInMempool,
    // When a registered TX SC Call hash has been executed by chain
    TransactionSCResult,
}

impl TMessage for Response {
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
        let server = self.server.clone();
        let address = ctx.address();
        let fut = async move {
            server.remove_client(&address).await;
        };
        ctx.wait(actix::fut::wrap_future(fut));
    }
}

impl Handler<Response> for WebSocketHandler {
    type Result = Result<(), RpcError>;

    fn handle(&mut self, msg: Response, ctx: &mut Self::Context) -> Self::Result {
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
        match request.method.as_str() {
            "subscribe" => {
                let params: SubscribeParams = serde_json::from_value(request.params.take().unwrap_or(Value::Null)).map_err(|e| RpcResponseError::new(request.id, RpcError::InvalidParams(e)))?;
                server.subscribe_client_to(addr, params.notify).await.map_err(|e| RpcResponseError::new(request.id, e))?;
                Ok(Value::Bool(true)) 
            },
            "unsubscribe" => {
                let params: SubscribeParams = serde_json::from_value(request.params.take().unwrap_or(Value::Null)).map_err(|e| RpcResponseError::new(request.id, RpcError::InvalidParams(e)))?;
                server.unsubscribe_client_from(addr, &params.notify).await.map_err(|e| RpcResponseError::new(request.id, e))?;
                Ok(Value::Bool(true)) 
            },
            _ => server.execute_method(request).await
        }
    }
}