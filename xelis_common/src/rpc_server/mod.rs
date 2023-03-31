pub mod websocket;
mod error;
mod handler;

pub use error::{RpcResponseError, InternalRpcError};
pub use handler::{RPCHandler, Handler};

use actix_ws::Message;
use async_trait::async_trait;

use std::{collections::HashMap, net::ToSocketAddrs, sync::Arc, hash::Hash};
use actix_web::{HttpResponse, dev::ServerHandle, HttpServer, App, web::{self, Data, Payload}, Responder, Error, Route, HttpRequest};
use serde::{Deserialize};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use log::debug;

use self::websocket::{WebSocketSessionShared, WebSocketServerShared, WebSocketServer, WebSocketHandler};

pub const JSON_RPC_VERSION: &str = "2.0";

#[derive(Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub id: Option<usize>,
    pub method: String,
    pub params: Option<Value>
}

pub struct EventWebSocketHandler<T: Sync + Send + Clone + 'static, E: Send + Eq + Hash + 'static> {
    sessions: Mutex<HashMap<WebSocketSessionShared<Self>, HashMap<E, Option<usize>>>>,
    handler: Arc<RPCHandler<T>>
}

impl<T, E> EventWebSocketHandler<T, E>
where
    T: Sync + Send + Clone + 'static,
    E: Send + Eq + Hash + 'static
{
    pub fn new(handler: Arc<RPCHandler<T>>) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            handler
        }
    }

    pub async fn notify(&self, event: &E, value: Value) {
        let sessions = self.sessions.lock().await;
        for (session, subscriptions) in sessions.iter() {
            if let Some(id) = subscriptions.get(event) {
                let response = json!({
                    "jsonrpc": JSON_RPC_VERSION,
                    "id": id,
                    "result": value
                });

                if let Err(e) = session.send_text(response.to_string()).await {
                    debug!("Error occured while notifying a new event: {}", e);
                };
            }
        }
    }
}


#[async_trait]
impl<T, E> WebSocketHandler for EventWebSocketHandler<T, E>
where
    T: Sync + Send + Clone + 'static,
    E: Send + Eq + Hash + 'static
{
    async fn on_close(&self, session: &WebSocketSessionShared<Self>) -> Result<(), anyhow::Error> {
        let mut sessions = self.sessions.lock().await;
        sessions.remove(session);
        Ok(())
    }

    async fn on_connection(&self, _: &WebSocketSessionShared<Self>) -> Result<(), anyhow::Error> {
        debug!("New connection detected on websocket");
        Ok(())
    }

    async fn on_message(&self, session: &WebSocketSessionShared<Self>, message: Message) -> Result<(), anyhow::Error> {
        if let Message::Text(text) = message {
            let response: Value = match self.handler.handle_request(text.as_bytes()).await {
                Ok(result) => result,
                Err(e) => e.to_json(),
            };
            session.send_text(response.to_string()).await?;
        }

        Ok(())
    }
}

pub struct RpcServer<T, E>
where
    T: Clone + Send + Sync + 'static,
    E: Send + Eq + Hash + 'static
{
    handle: Mutex<Option<ServerHandle>>, // keep the server handle to stop it gracefully
    websocket: Option<WebSocketServerShared<EventWebSocketHandler<T, E>>>,
    handler: Arc<RPCHandler<T>>
}

impl<T, E> RpcServer<T, E>
where
    T: Clone + Send + Sync + 'static,
    E: Send + Eq + Hash + 'static
{
    pub fn new(handler: RPCHandler<T>, use_websocket: bool) -> Self {
        let shared_handler = Arc::new(handler);
        let websocket = if use_websocket {
            let ws_handler = EventWebSocketHandler::new(shared_handler.clone());
            Some(WebSocketServer::new(ws_handler))
        } else {
            None
        };

        Self {
            handle: Mutex::new(None),
            handler: shared_handler,
            websocket,
        }
    }

    pub async fn start_with<A: ToSocketAddrs>(self, bind_address: A, closure: fn() -> Vec<(&'static str, Route)>) -> Result<Arc<Self>, Error> {
        let zelf = Arc::new(self);
        {
            let clone = Arc::clone(&zelf);
            let http_server = HttpServer::new(move || {
                let server = Arc::clone(&clone);
                let mut app = App::new().app_data(web::Data::new(server));
                app = app.route("/json_rpc", web::post().to(json_rpc::<T, E>));
                app = app.route("/ws", web::get().to(websocket::<T, E>));
                for (path, route) in closure() {
                    app = app.route(path, route);
                }
                app
            })
            .disable_signals()
            .bind(&bind_address)?
            .run();

            let mut handle = zelf.handle.lock().await;
            *handle = Some(http_server.handle());

            tokio::spawn(http_server);
        }

        Ok(zelf)
    }

    pub async fn stop(&self, graceful: bool) {
        if let Some(handler) = self.handle.lock().await.take() {
            handler.stop(graceful).await;
        }
    }

    pub fn get_rpc_handler(&self) -> &RPCHandler<T> {
        &self.handler
    }

    pub fn get_websocket(&self) -> &Option<WebSocketServerShared<EventWebSocketHandler<T, E>>> {
        &self.websocket
    }
}

// JSON RPC handler endpoint
async fn json_rpc<T, E>(server: Data<Arc<RpcServer<T, E>>>, body: web::Bytes) -> Result<impl Responder, RpcResponseError>
where
    T: Clone + Send + Sync + 'static,
    E: Send + Eq + Hash + 'static
{
    let result = server.get_rpc_handler().handle_request(&body).await?;
    Ok(HttpResponse::Ok().json(result))
}

// WebSocket JSON RPC handler endpoint
async fn websocket<T, E>(server: Data<Arc<RpcServer<T, E>>>, request: HttpRequest, body: Payload) -> Result<impl Responder, actix_web::Error>
where
    T: Clone + Send + Sync + 'static,
    E: Send + Eq + Hash + 'static
{
    if let Some(websocket) = server.get_websocket() {
        let response = websocket.handle_connection(&request, body).await?;
        Ok(response)
    } else {
        Ok(HttpResponse::NotFound().reason("WebSocket server is not enabled").finish())
    }
}