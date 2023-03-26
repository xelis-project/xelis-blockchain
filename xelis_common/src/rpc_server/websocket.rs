use std::{borrow::Borrow, sync::Arc, marker::PhantomData, hash::Hash};

use actix::{Actor, StreamHandler, AsyncContext, Message as TMessage, Handler, Addr};
use actix_web_actors::ws::{ProtocolError, Message, WebsocketContext};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{Value, json};
use log::{debug, trace};

use crate::{rpc_server::RpcResponseError, api::daemon::SubscribeParams};

use super::{InternalRpcError, RpcServerHandler, JSON_RPC_VERSION};

pub struct WSResponse<T: Borrow<Value> + ToString>(pub T);

impl<T: Borrow<Value> + ToString> TMessage for WSResponse<T> {
    type Result = Result<(), InternalRpcError>;
}

pub struct WebSocketHandler<T, E, H>
where
    T: Clone + Send + Sync + Unpin + 'static,
    E: DeserializeOwned + Serialize + Clone + ToOwned + Eq + Hash + Unpin + 'static,
    H: RpcServerHandler<T, E> + 'static
{
    server: Arc<H>,
    _phantom: PhantomData<(T, E)>
}

impl<T, E, H> Actor for WebSocketHandler<T, E, H>
where
    T: Clone + Send + Sync + Unpin + 'static,
    E: DeserializeOwned + Serialize + Clone + ToOwned + Eq + Hash + Unpin + 'static,
    H: RpcServerHandler<T, E> + 'static
{
    type Context = WebsocketContext<Self>;
}

impl<T, E, H> StreamHandler<Result<Message, ProtocolError>> for WebSocketHandler<T, E, H>
where
    T: Clone + Send + Sync + Unpin + 'static,
    E: DeserializeOwned + Serialize + Clone + ToOwned + Eq + Hash + Unpin + 'static,
    H: RpcServerHandler<T, E> + 'static
{
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
                    if let Err(e) = address.send(WSResponse(response)).await {
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
                    server.get_rpc_server().remove_client(&address).await;
                };
                ctx.wait(actix::fut::wrap_future(fut));
                ctx.close(reason);
            },
            msg => {
                debug!("Abnormal message received: {:?}. Closing connection", msg);
                let error = RpcResponseError::new(None, InternalRpcError::InvalidRequest);
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
            server.get_rpc_server().remove_client(&address).await;
        };
        ctx.wait(actix::fut::wrap_future(fut));
    }
}

impl<V: Borrow<Value> + ToString, T, E, H> Handler<WSResponse<V>> for WebSocketHandler<T, E, H>
where
    T: Clone + Send + Sync + Unpin + 'static,
    E: DeserializeOwned + Serialize + Clone + ToOwned + Eq + Hash + Unpin + 'static,
    H: RpcServerHandler<T, E> + 'static
{
    type Result = Result<(), InternalRpcError>;

    fn handle(&mut self, msg: WSResponse<V>, ctx: &mut Self::Context) -> Self::Result {
        ctx.text(msg.0.to_string());
        Ok(())
    }
}

impl<T, E, H> WebSocketHandler<T, E, H>
where
    T: Clone + Send + Sync + Unpin + 'static,
    E: DeserializeOwned + Serialize + Clone + ToOwned + Eq + Hash + Unpin + 'static,
    H: RpcServerHandler<T, E> + 'static
{
    pub fn new(server: Arc<H>) -> Self {
        Self {
            server,
            _phantom: PhantomData
        }
    }

    pub async fn handle_request(addr: &Addr<Self>, server: Arc<H>, body: &[u8]) -> Result<Value, RpcResponseError> {
        let mut request = server.get_rpc_server().parse_request(body)?;
        let method = request.method.as_str(); 
        match method {
            "subscribe" | "unsubscribe" => {
                let params: SubscribeParams<E> = serde_json::from_value(request.params.take().unwrap_or(Value::Null)).map_err(|e| RpcResponseError::new(request.id, InternalRpcError::InvalidParams(e)))?;
                let res = if method == "subscribe" {
                    server.get_rpc_server().subscribe_client_to(addr, params.notify, request.id).await
                } else {
                    server.get_rpc_server().unsubscribe_client_from(addr, &params.notify).await
                };
                res.map_err(|e| RpcResponseError::new(request.id, InternalRpcError::AnyError(e.into())))?;

                Ok(json!({
                    "jsonrpc": JSON_RPC_VERSION,
                    "id": request.id,
                    "result": json!(true)
                }))
            },
            _ => server.get_rpc_server().execute_method(server.get_data().clone(), request).await
        }
    }
}