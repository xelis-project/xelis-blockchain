use actix::{Actor, StreamHandler, AsyncContext, Message as TMessage, Handler};
use actix_web_actors::ws::{ProtocolError, Message, WebsocketContext};
use serde_json::Value;
use super::{SharedRpcServer, RpcError, RpcResponseError};
use log::debug;

struct Response(Value);

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
                    let response = match WebSocketHandler::handle_request(server, &text.as_bytes()).await {
                        Ok(result) => result,
                        Err(e) => e.to_json()
                    };
                    address.do_send(Response(response));
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

    fn finished(&mut self, ctx: &mut Self::Context) {
        let server = self.server.clone();
        let address = ctx.address();
        let fut = async move {
            server.remove_client(&address).await;
        };
        ctx.spawn(actix::fut::wrap_future(fut));
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

    pub async fn handle_request(server: SharedRpcServer, body: &[u8]) -> Result<Value, RpcResponseError> {
        let request = server.parse_request(body)?;
        // TODO check for subscribe method
        server.execute_method(request).await
    }
}