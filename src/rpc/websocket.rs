use actix::{Actor, StreamHandler};
use actix_web_actors::ws::{self, ProtocolError, Message, WebsocketContext};
use serde_json::{json, Value};
use super::{SharedRpcServer, RpcError, RpcResponseError};
use log::debug;

pub struct WebSocket {
    server: SharedRpcServer
}

impl Actor for WebSocket {
    type Context = WebsocketContext<Self>;
}

/// Handler for ws::Message message
impl StreamHandler<Result<Message, ProtocolError>> for WebSocket {
    fn handle(&mut self, msg: Result<Message, ProtocolError>, ctx: &mut Self::Context) {
        match msg {
            Ok(Message::Text(text)) => ctx.text("Hello World"),
            msg => {
                debug!("Abnormal message received: {:?}. Closing connection", msg);
                let error = RpcResponseError::new(None, RpcError::InvalidRequest);
                ctx.text(error.to_json().to_string());
                ctx.close(None)
            }
        }
    }
}

impl WebSocket {
    pub fn new(server: SharedRpcServer) -> Self {
        Self {
            server
        }
    }

    fn execute_rpc_method(&self) -> Result<Value, RpcError> {
        Ok(json!(""))
    }
}