use std::{
    borrow::Cow,
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::Arc,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Map, Value};
use metrics::{counter, histogram};
use log::{ trace, warn};
use schemars::{schema_for, JsonSchema, Schema};

use crate::{
    context::Context,
    time::Instant,
    rpc::{
        InternalRpcError,
        RpcRequest,
        RpcResponseError,
        JSON_RPC_VERSION
    }
};

// WASM doesn't support Send futures (single-threaded runtime)
#[cfg(not(target_arch = "wasm32"))]
pub type Handler = Box<
    dyn for<'a> Fn(&'a Context, Value) -> Pin<Box<dyn Future<Output = Result<Value, InternalRpcError>> + Send + 'a>>
    + Send + Sync
>;

#[cfg(target_arch = "wasm32")]
pub type Handler = Box<
    dyn for<'a> Fn(&'a Context, Value) -> Pin<Box<dyn Future<Output = Result<Value, InternalRpcError>> + 'a>>
    + Send + Sync
>;

#[cfg(not(target_arch = "wasm32"))]
pub type HandlerParams<P, R> = for<'a> fn(&'a Context, P) -> Pin<Box<dyn Future<Output = Result<R, InternalRpcError>> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub type HandlerParams<P, R> = for<'a> fn(&'a Context, P) -> Pin<Box<dyn Future<Output = Result<R, InternalRpcError>> + 'a>>;

#[cfg(not(target_arch = "wasm32"))]
pub type HandlerNoParams<R> = for<'a> fn(&'a Context) -> Pin<Box<dyn Future<Output = Result<R, InternalRpcError>> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub type HandlerNoParams<R> = for<'a> fn(&'a Context) -> Pin<Box<dyn Future<Output = Result<R, InternalRpcError>> + 'a>>;

// Information about an RPC method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcMethodInfo<'a> {
    pub name: Cow<'a, str>,
    pub schema: Cow<'a, RpcSchema>,
}

// Schema information about an RPC method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcSchema {
    pub params_schema: Option<Schema>,
    pub returns_schema: Schema,
}

/// An RPC method handler with its schema
pub struct MethodHandler {
    pub handler: Handler,
    pub schema: RpcSchema
}

pub struct RPCHandler<T: Send + Clone + 'static> {
    // all RPC methods registered
    methods: HashMap<String, MethodHandler>,
    data: T,
    batch_limit: Option<usize>
}

impl<T> RPCHandler<T>
where
    T: Send + Sync + Clone + 'static
{
    pub fn new(data: T, batch_limit: impl Into<Option<usize>>) -> Self {
        Self {
            methods: HashMap::new(),
            data,
            batch_limit: batch_limit.into()
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
            e @ Value::Object(_) => self.execute_method(&context, self.parse_request(e)?).await
                .map(|e| e.unwrap_or(Value::Null)),
            Value::Array(requests) => {
                if self.batch_limit.is_some_and(|v| requests.len() > v) {
                    return Err(RpcResponseError::new(None, InternalRpcError::BatchLimitExceeded))
                }

                let mut responses = Vec::with_capacity(requests.len());
                for value in requests {
                    if value.is_object() {
                        let request = self.parse_request(value)?;
                        let response = match self.execute_method(&context, request).await {
                            Ok(response) => response.unwrap_or_default(),
                            Err(e) => e.to_json()
                        };
                        responses.push(response);
                    } else {
                        responses.push(RpcResponseError::new(None, InternalRpcError::InvalidJSONRequest).to_json());
                    }
                }

                Ok(Value::Array(responses))
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

    pub fn has_method(&self, method_name: &str) -> bool {
        self.methods.contains_key(method_name)
    }

    pub async fn execute_method<'a>(&'a self, context: &'a Context, mut request: RpcRequest) -> Result<Option<Value>, RpcResponseError> {
        let handler = match self.methods.get(&request.method) {
            Some(handler) => handler,
            None => {
                if request.method == "schema" {
                    // Show all the methods registered
                    let methods: Vec<RpcMethodInfo> = self.methods.iter().map(|(name, handler)| {
                        RpcMethodInfo {
                            name: Cow::Borrowed(name),
                            schema: Cow::Borrowed(&handler.schema)
                        }
                    }).collect();

                    return Ok(Some(json!({
                        "jsonrpc": JSON_RPC_VERSION,
                        "id": request.id,
                        "result": methods
                    })));
                }

                trace!("unknown RPC method '{}'", request.method);
                return Err(RpcResponseError::new(request.id, InternalRpcError::MethodNotFound(request.method)))
            }
        };

        trace!("executing '{}' RPC method", request.method);
        counter!("xelis_rpc_calls", "method" => request.method.clone()).increment(1);

        let params = request.params.take().unwrap_or(Value::Null);

        let start = Instant::now();
        let result = (handler.handler)(context, params).await
            .map_err(|err| RpcResponseError::new(request.id.clone(), err))?;

        histogram!("xelis_rpc_calls_ms", "method" => request.method).record(start.elapsed().as_millis() as f64);

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
    pub fn register_method(&mut self, name: &str, handler: MethodHandler) {
        trace!("Registering RPC method: {}", name);
        if self.methods.insert(name.into(), handler).is_some() {
            warn!("The method '{}' was already registered !", name);
        }
    }

    // Register a method with parameters
    pub fn register_method_with_params<P, R>(
        &mut self,
        name: &str,
        f: HandlerParams<P, R>,
    )
    where
        P: JsonSchema + DeserializeOwned + Send + 'static,
        R: JsonSchema + Serialize + Send + 'static,
    {
        trace!("Registering RPC method with params: {}", name);
        let f = Arc::new(f);

        let handler: Handler = Box::new(move |ctx, body| {
            let f = Arc::clone(&f);
            Box::pin(async move {
                let params: P = parse_params(body)?;
                let res = f(ctx, params).await?;
                Ok(json!(res))
            })
        });

        self.register_method(name, MethodHandler {
            handler,
            schema: RpcSchema {
                params_schema: Some(schema_for!(P)),
                returns_schema: schema_for!(R),
            }
        });
    }

    // Register a method with parameters with a return schema given
    pub fn register_method_with_params_and_return_schema<P, R>(
        &mut self,
        name: &str,
        f: HandlerParams<P, Value>,
    )
    where
        P: JsonSchema + DeserializeOwned + Send + 'static,
        R: JsonSchema + Serialize + Send + 'static,
    {
        trace!("Registering RPC method with params: {}", name);
        let f = Arc::new(f);

        let handler: Handler = Box::new(move |ctx, body| {
            let f = Arc::clone(&f);
            Box::pin(async move {
                let params: P = parse_params(body)?;
                f(ctx, params).await
            })
        });

        self.register_method(name, MethodHandler {
            handler,
            schema: RpcSchema {
                params_schema: Some(schema_for!(P)),
                returns_schema: schema_for!(R),
            }
        });
    }

    // Register a method with no parameters
    pub fn register_method_no_params<R>(
        &mut self,
        name: &str,
        f: HandlerNoParams<R>
    )
    where
        R: JsonSchema + Serialize + Send + 'static
    {
        trace!("Registering RPC method with no params: {}", name);
        let f = Arc::new(f);

        let handler: Handler = Box::new(move |ctx, body| {
            let f = Arc::clone(&f);
            Box::pin(async move {
                require_no_params(body)?;
                let res = f(ctx).await?;
                Ok(json!(res))
            })
        });

        self.register_method(name, MethodHandler {
            handler,
            schema: RpcSchema {
                params_schema: None,
                returns_schema: schema_for!(R),
            }
        });
    }


    // Register a method with no parameters
    pub fn register_method_no_params_custom_return<R>(
        &mut self,
        name: &str,
        f: HandlerNoParams<Value>
    )
    where
        R: JsonSchema + Serialize + Send + 'static
    {
        trace!("Registering RPC method with no params: {}", name);
        let f = Arc::new(f);

        let handler: Handler = Box::new(move |ctx, body| {
            let f = Arc::clone(&f);
            Box::pin(async move {
                require_no_params(body)?;
                f(ctx).await
            })
        });

        self.register_method(name, MethodHandler {
            handler,
            schema: RpcSchema {
                params_schema: None,
                returns_schema: schema_for!(R),
            }
        });
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

// RPC Method with no params required
// Check that the params field is either null or empty
pub fn require_no_params(value: Value) -> Result<(), InternalRpcError> {
    if let Some(array) = value.as_array() {
        if !array.is_empty() {
            return Err(InternalRpcError::UnexpectedParams)
        }
    } else if !value.is_null() {
        return Err(InternalRpcError::UnexpectedParams)
    }

    Ok(())
}