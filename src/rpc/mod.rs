use crate::{core::{error::BlockchainError, blockchain::Blockchain}, config};
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder, dev::ServerHandle, ResponseError};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use std::{sync::Arc, collections::HashMap, pin::Pin, future::Future};
use log::info;
use anyhow::{Result, Error as AnyError};
use thiserror::Error;

const JSON_RPC_VERSION: &str = "2.0";

#[derive(Error, Debug)]
enum RpcError {
    #[error("Invalid request")]
    InvalidRequest,
    #[error("Expected json_rpc set to '2.0'")]
    InvalidVersion,
    #[error("Method '{}' in request was not found", _0)]
    MethodNotFound(String),
    #[error("Error: {}", _0)]
    AnyError(#[from] AnyError),
}

impl ResponseError for RpcError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::Ok().json(json!({
            "jsonrpc": JSON_RPC_VERSION,
            "id": 0, // TODO
            "error": {
                "code": -32700, // TODO
                "message": self.to_string()
            }
        }))
    }
}

pub type SharedRpcServer = web::Data<Arc<RpcServer>>;
pub type Handler = Box<dyn Fn(Arc<Blockchain>, Value) -> Pin<Box<dyn Future<Output = Result<Value>>>> + Send + Sync>;

#[derive(Deserialize)]
pub struct RpcRequest {
    jsonrpc: String,
    id: usize,
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
        let mut methods: HashMap<String, Handler> = HashMap::new();
        methods.insert("getheight".into(), Box::new(move |blockchain, _| {
            Box::pin(async move {
                Ok(json!(blockchain.get_height()))
            })
        }));

        let server = Self {
            handle: Mutex::new(None),
            methods,
            blockchain
        };

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
            handler.stop(true).await;
        }
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

#[post("/json_rpc")]
async fn json_rpc(rpc: SharedRpcServer, body: web::Bytes) -> Result<impl Responder, RpcError> {
    let rpc_request: RpcRequest = serde_json::from_slice(&body).map_err(|_| RpcError::InvalidRequest)?;
    if rpc_request.jsonrpc != JSON_RPC_VERSION {
        return Err(RpcError::InvalidVersion);
    }

    let handler = rpc.get_registered_methods().get(&rpc_request.method).ok_or(RpcError::MethodNotFound(rpc_request.method))?;
    let result = handler(Arc::clone(rpc.get_blockchain()), rpc_request.params.unwrap_or(Value::Null)).await?;
    Ok(HttpResponse::Ok().json(json!({
        "jsonrpc": JSON_RPC_VERSION,
        "id": rpc_request.id,
        "result": result
    })))
}