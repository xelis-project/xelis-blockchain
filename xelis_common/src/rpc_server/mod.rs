pub mod websocket;
mod error;

pub use error::{RpcResponseError, InternalRpcError};

use std::{collections::HashMap, pin::Pin, future::Future, net::ToSocketAddrs, sync::Arc};
use actix_web::{HttpResponse, dev::ServerHandle, HttpServer, App, web::{self, Data}, Responder, Error, Route};
use serde::{Deserialize};
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

pub struct RpcServer<T>
where
    T: Clone + Send + Sync + 'static,
{
    handle: Mutex<Option<ServerHandle>>, // keep the server handle to stop it gracefully
    methods: HashMap<String, Handler<T>>, // all rpc methods registered
    data: T
}

impl<T> RpcServer<T>
where
    T: Clone + Send + Sync + 'static,
{
    pub fn new(data: T) -> Self {
        Self {
            handle: Mutex::new(None),
            methods: HashMap::new(),
            data
        }
    }

    pub async fn start_with<A: ToSocketAddrs>(self, bind_address: A, closure: fn() -> Vec<(&'static str, Route)>) -> Result<Arc<Self>, Error> {
        let zelf = Arc::new(self);
        {
            let clone = Arc::clone(&zelf);
            let http_server = HttpServer::new(move || {
                let server = Arc::clone(&clone);
                let mut app = App::new().app_data(web::Data::new(server));
                app = app.route("/json_rpc", web::post().to(json_rpc::<T>));
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

    pub fn get_data(&self) -> &T {
        &self.data
    }
}

// JSON RPC handler endpoint
async fn json_rpc<T>(server: Data<Arc<RpcServer<T>>>, body: web::Bytes) -> Result<impl Responder, RpcResponseError>
where
    T: Clone + Send + Sync + 'static
{
    let request = server.parse_request(&body)?;
    let result = server.execute_method(server.get_data().clone(), request).await?;
    Ok(HttpResponse::Ok().json(result))
}