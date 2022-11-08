use actix::{Actor, StreamHandler, AsyncContext, Addr};
use actix_web_actors::ws::{ProtocolError, Message, WebsocketContext};
use serde_json::Value;
use super::{SharedRpcServer, RpcError, RpcResponseError};
use log::debug;

enum Action {
    Notify(Addr<WebSocketHandler>, Value),
    Register(Addr<WebSocketHandler>)
}

pub struct WebSocketHandler {
    server: SharedRpcServer
}

impl Actor for WebSocketHandler {
    type Context = WebsocketContext<Self>;
}

/// Handler for ws::Message message
impl StreamHandler<Result<Message, ProtocolError>> for WebSocketHandler {
    fn handle(&mut self, msg: Result<Message, ProtocolError>, ctx: &mut Self::Context) {
        match msg {
            Ok(Message::Text(text)) => {
                let address = ctx.address();
                let server = self.server.clone();
                let fut = async move {
                    let response = match WebSocketHandler::handle_request(server, &text.as_bytes()).await {
                        Ok(result) => result.to_string(),
                        Err(e) => e.to_json().to_string()
                    };
                    // TODO send response to client
                    // ctx.text(response.to_string());
                };
                let fut = actix::fut::wrap_future(fut);
                ctx.spawn(fut);
            },
            msg => {
                debug!("Abnormal message received: {:?}. Closing connection", msg);
                let error = RpcResponseError::new(None, RpcError::InvalidRequest);
                ctx.text(error.to_json().to_string());
                ctx.close(None);
            }
        }
    }
}

impl WebSocketHandler {
    pub fn new(server: SharedRpcServer) -> Self {
        Self {
            server
        }
    }

    pub async fn handle_request(server: SharedRpcServer, body: &[u8]) -> Result<Value, RpcResponseError> {
        let request = server.parse_request(body)?;
        // TODO check for subscribe method
        server.execute_method(request).await
    }
}