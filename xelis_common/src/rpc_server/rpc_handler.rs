use std::{collections::HashMap, pin::Pin, future::Future};
use serde::de::DeserializeOwned;
use serde_json::{json, Map, Value};
use crate::context::Context;

use super::{InternalRpcError, RpcResponseError, RpcRequest, JSON_RPC_VERSION};
use log::{error, trace};

pub type Handler = fn(&'_ Context, Value) -> Pin<Box<dyn Future<Output = Result<Value, InternalRpcError>> + Send + '_>>;

pub struct RPCHandler<T: Send + Clone + 'static> {
    methods: HashMap<String, Handler>, // all RPC methods registered
    data: T
}

impl<T> RPCHandler<T>
where
    T: Send + Sync + Clone + 'static
{
    pub fn new(data: T) -> Self {
        Self {
            methods: HashMap::new(),
            data
        }
    }

    pub async fn handle_request(&self, body: &[u8]) -> Result<Value, RpcResponseError> {
        let mut context = Context::new();

        // Add the data
        context.store(self.get_data().clone());

        self.handle_request_with_context(context, body).await
    }

    pub async fn handle_request_with_context(&self, context: Context, body: &[u8]) -> Result<Value, RpcResponseError> {
        let request: Value = serde_json::from_slice(body)
            .map_err(|_| RpcResponseError::new(None, InternalRpcError::ParseBodyError))?;

        match request {
            e @ Value::Object(_) => self.execute_method(&context, self.parse_request(e)?).await.map(|e| e.unwrap_or(Value::Null)),
            Value::Array(requests) => {
                let mut responses = Vec::new();
                for value in requests {
                    if value.is_object() {
                        let request = self.parse_request(value)?;
                        let response = match self.execute_method(&context, request).await {
                            Ok(response) => json!(response),
                            Err(e) => e.to_json()
                        };
                        responses.push(response);
                    } else {
                        responses.push(RpcResponseError::new(None, InternalRpcError::InvalidJSONRequest).to_json());
                    }
                }
                Ok(serde_json::to_value(responses).map_err(|err| RpcResponseError::new(None, InternalRpcError::SerializeResponse(err)))?)
            },
            _ => return Err(RpcResponseError::new(None, InternalRpcError::InvalidJSONRequest))
        }
    }

    pub fn parse_request_from_bytes(&self, body: &[u8]) -> Result<RpcRequest, RpcResponseError> {
        let request: Value = serde_json::from_slice(body)
            .map_err(|_| RpcResponseError::new(None, InternalRpcError::ParseBodyError))?;
        self.parse_request(request)
    }

    pub fn parse_request(&self, body: Value) -> Result<RpcRequest, RpcResponseError> {
        let request: RpcRequest = serde_json::from_value(body).map_err(|_| RpcResponseError::new(None, InternalRpcError::ParseBodyError))?;
        if request.jsonrpc != JSON_RPC_VERSION {
            return Err(RpcResponseError::new(request.id, InternalRpcError::InvalidVersion));
        }
        Ok(request)
    }

    pub fn has_method(&self, method_name: &String) -> bool {
        self.methods.contains_key(method_name)
    }

    pub async fn execute_method<'a>(&'a self, context: &'a Context, mut request: RpcRequest) -> Result<Option<Value>, RpcResponseError> {
        let handler = match self.methods.get(&request.method) {
            Some(handler) => handler,
            None => return Err(RpcResponseError::new(request.id, InternalRpcError::MethodNotFound(request.method)))
        };
        trace!("executing '{}' RPC method", request.method);
        let params = request.params.take().unwrap_or(Value::Null);
        let result = handler(context, params).await.map_err(|err| RpcResponseError::new(request.id.clone(), err))?;
        Ok(if request.id.is_some() {
            Some(json!({
                "jsonrpc": JSON_RPC_VERSION,
                "id": request.id,
                "result": result
            }))
        } else {
            None
        })
    }

    // register a new RPC method handler
    pub fn register_method(&mut self, name: &str, handler: Handler) {
        if self.methods.insert(name.into(), handler).is_some() {
            error!("The method '{}' was already registered !", name);
        }
    }

    pub fn get_data(&self) -> &T {
        &self.data
    }
}

pub fn parse_params<P: DeserializeOwned>(mut value: Value) -> Result<P, InternalRpcError> {
    if value.is_null() {
        value = Value::Object(Map::new());
    }

    serde_json::from_value(value).map_err(|e| InternalRpcError::InvalidJSONParams(e))
}