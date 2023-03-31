use std::{collections::HashMap, pin::Pin, future::Future};
use serde_json::{Value, json};
use super::{InternalRpcError, RpcResponseError, RpcRequest, JSON_RPC_VERSION};
use log::{error, trace};

pub type Handler<T> = fn(&T, Value) -> Pin<Box<dyn Future<Output = Result<Value, InternalRpcError>> + Send>>;

pub struct RPCHandler<T> {
    methods: HashMap<String, Handler<T>>, // all RPC methods registered
    data: T
}

impl<T> RPCHandler<T> {
    pub fn new(data: T) -> Self {
        Self {
            methods: HashMap::new(),
            data
        }
    }

    pub async fn handle_request(&self, body: &[u8]) -> Result<Value, RpcResponseError> {
        let request = self.parse_request(body)?;
        self.execute_method(request).await
    }

    pub fn parse_request(&self, body: &[u8]) -> Result<RpcRequest, RpcResponseError> {
        let request: RpcRequest = serde_json::from_slice(&body).map_err(|_| RpcResponseError::new(None, InternalRpcError::ParseBodyError))?;
        if request.jsonrpc != JSON_RPC_VERSION {
            return Err(RpcResponseError::new(request.id, InternalRpcError::InvalidVersion));
        }
        Ok(request)
    }

    pub async fn execute_method(&self, mut request: RpcRequest) -> Result<Value, RpcResponseError> {
        let handler = match self.methods.get(&request.method) {
            Some(handler) => handler,
            None => return Err(RpcResponseError::new(request.id, InternalRpcError::MethodNotFound(request.method)))
        };
        trace!("executing '{}' RPC method", request.method);
        let params = request.params.take().unwrap_or(Value::Null);
        let result = handler(self.get_data(), params).await.map_err(|err| RpcResponseError::new(request.id, err))?;
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