pub mod rpc;

use crate::{core::{error::BlockchainError, blockchain::Blockchain, reader::ReaderError}, config};
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder, dev::ServerHandle, ResponseError};
use serde::Deserialize;
use serde_json::{Value, Error as SerdeError, json};
use tokio::sync::Mutex;
use std::{sync::Arc, collections::HashMap, pin::Pin, future::Future, fmt::{Display, Formatter}};
use log::{trace, info};
use anyhow::Error as AnyError;
use thiserror::Error;

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
    ExpectedNormalAddress
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
struct RpcResponseError {
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
}

impl Display for RpcResponseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "RpcError[id: {}, error: {}]", self.get_id(), self.error.to_string())
    }
}

impl ResponseError for RpcResponseError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::Ok().json(json!({
            "jsonrpc": JSON_RPC_VERSION,
            "id": self.get_id(),
            "error": {
                "code": self.error.get_code(),
                "message": self.error.to_string()
            }
        }))
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
    methods: HashMap<String, Handler>,
    blockchain: Arc<Blockchain>
}

impl RpcServer {
    pub async fn new(bind_address: String, blockchain: Arc<Blockchain>) -> Result<Arc<Self>, BlockchainError> {
        let mut server = Self {
            handle: Mutex::new(None),
            methods: HashMap::new(),
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
        })
        .disable_signals()
        .bind(&bind_address)?
        .run();
        let handle = server.handle();
        *rpc_server.handle.lock().await = Some(handle);

        // start the http server
        info!("Starting RPC server on: http://{}", bind_address);
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

    pub fn register_method(&mut self, name: &str, handler: Handler) {
        self.methods.insert(name.into(), handler);
    }

    pub fn get_registered_methods(&self) -> &HashMap<String, Handler> {
        &self.methods
    }

    pub fn get_blockchain(&self) -> &Arc<Blockchain> {
        &self.blockchain
    }
}

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body(format!("Hello, world!\nRunning on: {}", config::VERSION))
}

// TODO support batch
#[post("/json_rpc")]
async fn json_rpc(rpc: SharedRpcServer, body: web::Bytes) -> Result<impl Responder, RpcResponseError> {
    let mut rpc_request: RpcRequest = serde_json::from_slice(&body).map_err(|_| RpcResponseError::new(None, RpcError::ParseBodyError))?;
    if rpc_request.jsonrpc != JSON_RPC_VERSION {
        return Err(RpcResponseError::new(rpc_request.id, RpcError::InvalidVersion));
    }

    let handler = match rpc.get_registered_methods().get(&rpc_request.method) {
        Some(handler) => handler,
        None => return Err(RpcResponseError::new(rpc_request.id, RpcError::MethodNotFound(rpc_request.method)))
    };
    trace!("executing '{}' RPC method", rpc_request.method);
    let result = handler(Arc::clone(rpc.get_blockchain()), rpc_request.params.take().unwrap_or(Value::Null)).await.map_err(|err| RpcResponseError::new(rpc_request.id, err.into()))?;
    Ok(HttpResponse::Ok().json(json!({
        "jsonrpc": JSON_RPC_VERSION,
        "id": rpc_request.id,
        "result": result
    })))
}