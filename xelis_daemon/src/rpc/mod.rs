pub mod rpc;
pub mod websocket;

use crate::core::{error::BlockchainError, blockchain::Blockchain};
use crate::rpc::websocket::WebSocketHandler;
use actix::{Addr, MailboxError};
use actix_web::{get, post, web::{self, Payload}, error::Error, App, HttpResponse, HttpServer, Responder, dev::ServerHandle, ResponseError, HttpRequest};
use actix_web_actors::ws::WsResponseBuilder;
use serde::{Deserialize, Serialize};
use serde_json::{Value, Error as SerdeError, json};
use tokio::sync::Mutex;
use xelis_common::config;
use xelis_common::serializer::ReaderError;
use std::{sync::Arc, collections::{HashMap, HashSet}, pin::Pin, future::Future, fmt::{Display, Formatter}};
use log::{trace, info};
use anyhow::Error as AnyError;
use thiserror::Error;
use self::websocket::{NotifyEvent, Response};

pub type SharedRpcServer = web::Data<Arc<RpcServer>>;
pub type Handler = Box<dyn Fn(Arc<Blockchain>, Value) -> Pin<Box<dyn Future<Output = Result<Value, RpcError>>>> + Send + Sync>;

const JSON_RPC_VERSION: &str = "2.0";

#[derive(Error, Debug)]
pub enum RpcError {
    #[error("Invalid body in request")]
    ParseBodyError,
    #[error("Invalid request")]
    InvalidRequest,
    #[error("Invalid params: {}", _0)]
    InvalidParams(#[from] SerdeError),
    #[error("Unexpected parameters for this method")]
    UnexpectedParams,
    #[error("Expected json_rpc set to '2.0'")]
    InvalidVersion,
    #[error("Method '{}' in request was not found", _0)]
    MethodNotFound(String),
    #[error("Error: {}", _0)]
    BlockchainError(#[from] BlockchainError),
    #[error("Error: {}", _0)]
    DeserializerError(#[from] ReaderError),
    #[error("Error: {}", _0)]
    AnyError(#[from] AnyError),
    #[error("Error, expected a normal wallet address")]
    ExpectedNormalAddress,
    #[error("Error, no P2p enabled")]
    NoP2p,
    #[error("WebSocket client is not registered")]
    ClientNotRegistered,
    #[error("Could not send message to address: {}", _0)]
    WebSocketSendError(#[from] MailboxError)
}

impl RpcError {
    pub fn get_code(&self) -> i16 {
        match self {
            RpcError::ParseBodyError => -32700,
            RpcError::InvalidRequest | RpcError::InvalidVersion => -32600,
            RpcError::MethodNotFound(_) => -32601,
            RpcError::InvalidParams(_) | RpcError::UnexpectedParams => -32602,
            _ => -32603
        }
    }
}

#[derive(Debug)]
pub struct RpcResponseError {
    id: Option<usize>,
    error: RpcError
}

impl RpcResponseError {
    pub fn new(id: Option<usize>, error: RpcError) -> Self {
        Self {
            id,
            error
        }
    }

    pub fn get_id(&self) -> Value {
        match self.id {
            Some(id) => json!(id),
            None => Value::Null
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "jsonrpc": JSON_RPC_VERSION,
            "id": self.get_id(),
            "error": {
                "code": self.error.get_code(),
                "message": self.error.to_string()
            }
        })
    }
}

impl Display for RpcResponseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "RpcError[id: {}, error: {}]", self.get_id(), self.error.to_string())
    }
}

impl ResponseError for RpcResponseError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::Ok().json(self.to_json())
    }
}

#[derive(Deserialize)]
pub struct RpcRequest {
    jsonrpc: String,
    id: Option<usize>,
    method: String,
    params: Option<Value>
}

pub struct RpcServer {
    handle: Mutex<Option<ServerHandle>>, // keep the server handle to stop it gracefully
    methods: HashMap<String, Handler>, // all rpc methods registered
    blockchain: Arc<Blockchain>, // pointer to blockchain data
    clients: Mutex<HashMap<Addr<WebSocketHandler>, HashSet<NotifyEvent>>> // all websocket clients connected with subscriptions linked
}

impl RpcServer {
    pub async fn new(bind_address: String, blockchain: Arc<Blockchain>) -> Result<Arc<Self>, BlockchainError> {
        let mut server = Self {
            handle: Mutex::new(None),
            methods: HashMap::new(),
            clients: Mutex::new(HashMap::new()),
            blockchain
        };
        rpc::register_methods(&mut server);

        let rpc_server = Arc::new(server);
        let rpc_clone = Arc::clone(&rpc_server);
        let server = HttpServer::new(move || {
            let rpc = Arc::clone(&rpc_clone);
            App::new()
                .app_data(web::Data::new(rpc))
                .service(index)
                .service(json_rpc)
                .service(ws_endpoint)
        })
        .disable_signals()
        .bind(&bind_address)?
        .run();
        let handle = server.handle();
        *rpc_server.handle.lock().await = Some(handle);

        // start the http server
        info!("RPC server will listen on: http://{}", bind_address);
        tokio::spawn(server);
        Ok(rpc_server)
    }

    pub async fn stop(&self) {
        info!("Stopping RPC Server...");
        if let Some(handler) = self.handle.lock().await.take() {
            handler.stop(false).await;
        }
        info!("RPC Server is now stopped!");
    }

    pub fn parse_request(&self, body: &[u8]) -> Result<RpcRequest, RpcResponseError> {
        let request: RpcRequest = serde_json::from_slice(&body).map_err(|_| RpcResponseError::new(None, RpcError::ParseBodyError))?;
        if request.jsonrpc != JSON_RPC_VERSION {
            return Err(RpcResponseError::new(request.id, RpcError::InvalidVersion));
        }
        Ok(request)
    }

    pub async fn execute_method(&self, mut request: RpcRequest) -> Result<Value, RpcResponseError> {

        let handler = match self.methods.get(&request.method) {
            Some(handler) => handler,
            None => return Err(RpcResponseError::new(request.id, RpcError::MethodNotFound(request.method)))
        };
        trace!("executing '{}' RPC method", request.method);
        let result = handler(Arc::clone(&self.blockchain), request.params.take().unwrap_or(Value::Null)).await.map_err(|err| RpcResponseError::new(request.id, err.into()))?;
        Ok(json!({
            "jsonrpc": JSON_RPC_VERSION,
            "id": request.id,
            "result": result
        }))
    }

    pub fn register_method(&mut self, name: &str, handler: Handler) {
        self.methods.insert(name.into(), handler);
    }

    pub fn get_blockchain(&self) -> &Arc<Blockchain> {
        &self.blockchain
    }

    pub async fn add_client(&self, addr: Addr<WebSocketHandler>) {
        let mut clients = self.clients.lock().await;
        clients.insert(addr, HashSet::new());
    }

    pub async fn remove_client(&self, addr: &Addr<WebSocketHandler>) {
        let mut clients = self.clients.lock().await;
        let deleted = clients.remove(addr).is_some();
        trace!("WebSocket client {:?} deleted: {}", addr, deleted);
    }

    pub async fn subscribe_client_to(&self, addr: &Addr<WebSocketHandler>, subscribe: NotifyEvent) -> Result<(), RpcError> {
        let mut clients = self.clients.lock().await;
        let subscriptions = clients.get_mut(addr).ok_or_else(|| RpcError::ClientNotRegistered)?;
        subscriptions.insert(subscribe);
        Ok(())
    }

    pub async fn unsubscribe_client_from(&self, addr: &Addr<WebSocketHandler>, subscribe: &NotifyEvent) -> Result<(), RpcError> {
        let mut clients = self.clients.lock().await;
        let subscriptions = clients.get_mut(addr).ok_or_else(|| RpcError::ClientNotRegistered)?;
        subscriptions.remove(subscribe);
        Ok(())
    }

    pub async fn notify_clients<V: Serialize>(&self, notify: NotifyEvent, value: V) -> Result<(), RpcError> {
        let clients = self.clients.lock().await;
        for (addr, subs) in clients.iter() {
            if subs.contains(&notify) {
                addr.send(Response(json!(value))).await??;
            }
        }
        Ok(())
    }
}

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body(format!("Hello, world!\nRunning on: {}", config::VERSION))
}

// TODO support batch
#[post("/json_rpc")]
async fn json_rpc(rpc: SharedRpcServer, body: web::Bytes) -> Result<impl Responder, RpcResponseError> {
    let request = rpc.parse_request(&body)?;
    let result = rpc.execute_method(request).await?;
    Ok(HttpResponse::Ok().json(result))
}

#[get("/ws")]
async fn ws_endpoint(server: SharedRpcServer, request: HttpRequest, stream: Payload) -> Result<HttpResponse, Error> {
    let (addr, response) = WsResponseBuilder::new(WebSocketHandler::new(server.clone()), &request, stream).start_with_addr()?;
    trace!("New client connected to WebSocket: {:?}", addr);
    server.add_client(addr).await;

    Ok(response)
}