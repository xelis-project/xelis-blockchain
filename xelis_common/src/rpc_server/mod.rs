mod error;

pub use error::{RpcResponseError, InternalRpcError};

use std::{collections::HashMap, pin::Pin, future::Future, net::ToSocketAddrs, sync::Arc};
use actix_web::{HttpResponse, dev::ServerHandle, HttpServer, App, web::{self, Data}, Responder, Error, Route};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use log::{trace, error};

pub const JSON_RPC_VERSION: &str = "2.0";

#[derive(Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub id: Option<usize>,
    pub method: String,
    pub params: Option<Value>
}

pub type Handler<T> = fn(T, Value) -> Pin<Box<dyn Future<Output = Result<Value, InternalRpcError>>>>;

pub trait RpcServerHandler<T: Clone + Send + Sync + 'static> {
    fn get_rpc_server(&self) -> &RpcServer<T>;
    fn get_data(&self) -> &T;
}

pub struct RpcServer<T: Clone + Send + Sync + 'static> {
    handle: Mutex<Option<ServerHandle>>, // keep the server handle to stop it gracefully
    methods: HashMap<String, Handler<T>>, // all rpc methods registered
}

impl<T: Clone + Send + Sync + 'static> RpcServer<T> {
    pub fn new() -> Self {
        Self {
            handle: Mutex::new(None),
            methods: HashMap::new()
        }
    }

    pub async fn start_with<A: ToSocketAddrs, H: RpcServerHandler<T> + Send + Sync + 'static>(&self, server: Arc<H>, bind_address: A, closure: fn() -> Vec<(&'static str, Route)>) -> Result<(), Error> {
        {
            let http_server = HttpServer::new(move || {
                let server = server.clone();
                let mut app = App::new().app_data(web::Data::new(server));
                app = app.route("/json_rpc", web::post().to(json_rpc::<T, H>));
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

    pub fn register_method(&mut self, name: &str, handler: Handler<T>) {
        if self.methods.insert(name.into(), handler).is_some() {
            error!("The method '{}' was already registered !", name);
        }
    }
}

async fn json_rpc<T: Sync + Send + Clone + 'static, H: RpcServerHandler<T> + Send + Sync + 'static>(server: Data<Arc<H>>, body: web::Bytes) -> Result<impl Responder, RpcResponseError> {
    let rpc_server = server.get_rpc_server();
    let request = rpc_server.parse_request(&body)?;
    let result = rpc_server.execute_method(server.get_data().clone(), request).await?;
    Ok(HttpResponse::Ok().json(result))
}