mod error;
mod websocket;

use actix_ws::Session;
pub use error::{RpcResponseError, InternalRpcError};

use std::{collections::HashMap, pin::Pin, future::Future, net::ToSocketAddrs, sync::Arc, borrow::Cow, hash::Hash};
use actix_web::{HttpResponse, dev::ServerHandle, HttpServer, App, web::{self, Data, Payload}, Responder, Error, Route, HttpRequest};
use serde::{Deserialize, de::DeserializeOwned, Serialize};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use log::{trace, error, debug};
use crate::api::daemon::EventResult;

use self::websocket::{WebSocketServerShared, WebSocketServer};

pub const JSON_RPC_VERSION: &str = "2.0";

#[derive(Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub id: Option<usize>,
    pub method: String,
    pub params: Option<Value>
}

pub type Handler<T> = fn(T, Value) -> Pin<Box<dyn Future<Output = Result<Value, InternalRpcError>>>>;

pub trait RpcServerHandler<T, E>: Sized
where
    T: Clone + Send + Sync + Unpin + 'static,
    E: DeserializeOwned + Serialize + Clone + ToOwned + Eq + Hash + Unpin + 'static
{
    fn get_rpc_server(&self) -> &RpcServer<T, E>;
    fn get_data(&self) -> &T;
}

pub struct RpcServer<T, E>
where
    T: Clone + Send + Sync + Unpin + 'static,
    E: DeserializeOwned + Serialize + Clone + ToOwned + Eq + Hash + Unpin + 'static
{
    handle: Mutex<Option<ServerHandle>>, // keep the server handle to stop it gracefully
    clients: Mutex<HashMap<Session, HashMap<E, Option<usize>>>>, // all websocket clients connected with subscriptions linked
    methods: HashMap<String, Handler<T>>, // all rpc methods registered
    websocket: WebSocketServerShared
}

impl<T, E> RpcServer<T, E>
where
    T: Clone + Send + Sync + Unpin + 'static,
    E: DeserializeOwned + Serialize + Clone + ToOwned + Eq + Hash + Unpin + 'static,
{
    pub fn new() -> Self {
        Self {
            handle: Mutex::new(None),
            clients: Mutex::new(HashMap::new()),
            methods: HashMap::new(),
            websocket: WebSocketServer::new()
        }
    }

    pub async fn start_with<A: ToSocketAddrs, H: RpcServerHandler<T, E> + Send + Sync + 'static>(&self, server: Arc<H>, bind_address: A, closure: fn() -> Vec<(&'static str, Route)>) -> Result<(), Error> {
        {
            let http_server = HttpServer::new(move || {
                let server = server.clone();
                let mut app = App::new().app_data(web::Data::new(server));
                app = app.route("/json_rpc", web::post().to(json_rpc::<T, E, H>))
                    .route("/ws", web::post().to(websocket::<T, E, H>));
                for (path, route) in closure() {
                    app = app.route(path, route);
                }
                app
            })
            .disable_signals()
            .bind(&bind_address)?
            .run();

            let mut handle = self.handle.lock().await;
            *handle = Some(http_server.handle());

            tokio::spawn(http_server);
        }

        Ok(())
    }

    pub async fn stop(&self, graceful: bool) {
        if let Some(handler) = self.handle.lock().await.take() {
            handler.stop(graceful).await;
        }
    }

    pub fn parse_request(&self, body: &[u8]) -> Result<RpcRequest, RpcResponseError> {
        let request: RpcRequest = serde_json::from_slice(&body).map_err(|_| RpcResponseError::new(None, InternalRpcError::ParseBodyError))?;
        if request.jsonrpc != JSON_RPC_VERSION {
            return Err(RpcResponseError::new(request.id, InternalRpcError::InvalidVersion));
        }
        Ok(request)
    }

    pub async fn execute_method(&self, data: T, mut request: RpcRequest) -> Result<Value, RpcResponseError> {
        let handler = match self.methods.get(&request.method) {
            Some(handler) => handler,
            None => return Err(RpcResponseError::new(request.id, InternalRpcError::MethodNotFound(request.method)))
        };
        trace!("executing '{}' RPC method", request.method);
        let result = handler(data, request.params.take().unwrap_or(Value::Null)).await.map_err(|err| RpcResponseError::new(request.id, err.into()))?;
        Ok(json!({
            "jsonrpc": JSON_RPC_VERSION,
            "id": request.id,
            "result": result
        }))
    }

    // register a new RPC method handler
    pub fn register_method(&mut self, name: &str, handler: Handler<T>) {
        if self.methods.insert(name.into(), handler).is_some() {
            error!("The method '{}' was already registered !", name);
        }
    }

    // notify all clients connected to the websocket which have subscribed to the event sent.
    // each client message is sent through a tokio task in case an error happens and to prevent waiting on others clients
    /*pub async fn notify_clients(&self, event_type: &E, value: Value) -> Result<(), InternalRpcError> {
        let value = json!(EventResult { event: Cow::Borrowed(event_type), value });
        let clients = self.clients.lock().await;
        for (addr, subs) in clients.iter() {
            if let Some(id) = subs.get(event_type) {
                let addr = addr.clone();
                let response = WSResponse(json!({
                    "jsonrpc": JSON_RPC_VERSION,
                    "id": id,
                    "result": value
                }));
                tokio::spawn(async move {
                    match addr.send(response).await {
                        Ok(response) => {
                            if let Err(e) = response {
                                debug!("Error while sending websocket event: {} ", e);
                            } 
                        }
                        Err(e) => {
                            debug!("Error while sending on mailbox: {}", e);
                        }
                    };
                });
            }
        }
        Ok(())
    }*/

    // get all websocket clients
    pub fn get_clients(&self) -> &Mutex<HashMap<Session, HashMap<E, Option<usize>>>> {
        &self.clients
    }

    pub fn get_websocket(&self) -> &WebSocketServerShared {
        &self.websocket
    }
}

// JSON RPC handler endpoint
async fn json_rpc<T, E, H>(server: Data<Arc<H>>, body: web::Bytes) -> Result<impl Responder, RpcResponseError>
where
    T: Clone + Send + Sync + Unpin + 'static,
    E: DeserializeOwned + Serialize + Clone + ToOwned + Eq + Hash + Unpin + 'static,
    H: RpcServerHandler<T, E> + 'static
{
    let rpc_server = server.get_rpc_server();
    let request = rpc_server.parse_request(&body)?;
    let result = rpc_server.execute_method(server.get_data().clone(), request).await?;
    Ok(HttpResponse::Ok().json(result))
}

// JSON RPC handler websocket endpoint
async fn websocket<T, E, H>(server: Data<Arc<H>>, request: HttpRequest, body: Payload) -> Result<HttpResponse, Error>
where
    T: Clone + Send + Sync + Unpin + 'static,
    E: DeserializeOwned + Serialize + Clone + ToOwned + Eq + Hash + Unpin + 'static,
    H: RpcServerHandler<T, E> + 'static
{
    let ws = server.get_rpc_server().get_websocket();
    ws.handle_connection(&request, body).await
}