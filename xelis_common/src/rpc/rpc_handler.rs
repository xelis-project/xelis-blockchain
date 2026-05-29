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
use log::trace;
use schemars::{schema_for, JsonSchema, Schema};
use crate::{
    async_handler,
    time::Instant,
    rpc::{
        InternalRpcError,
        RpcRequest,
        RpcResponseError,
        JSON_RPC_VERSION
    }
};

// Re-export the necessary types and traits for RPC handling
pub use runtime_context::{Context, ShareableTid, tid};

// Type definition for an RPC method handler
// It is a boxed function that takes a context reference and a JSON value as parameters
// and returns a pinned future that resolves to a Result containing a JSON value or an InternalRpcError
// It is Send and Sync to allow safe sharing across threads and async contexts
pub type Handler = Box<
    dyn for<'a> Fn(&'a Context, Value) -> Pin<Box<dyn Future<Output = Result<Value, InternalRpcError>> + Send + 'a>>
    + Send + Sync
>;

pub type HandlerParams<P, R> = for<'a> fn(&'a Context, P) -> Pin<Box<dyn Future<Output = Result<R, InternalRpcError>> + Send + 'a>>;

pub type HandlerNoParams<R> = for<'a> fn(&'a Context) -> Pin<Box<dyn Future<Output = Result<R, InternalRpcError>> + Send + 'a>>;

// Information about an RPC method
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RpcMethodInfo<'a> {
    pub name: Cow<'a, str>,
    pub schema: Cow<'a, RpcSchema>,
}

// Schema information about an RPC method
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RpcSchema {
    pub params_schema: Option<Schema>,
    pub returns_schema: Schema,
}

/// An RPC method handler with its schema
pub struct MethodHandler {
    pub handler: Handler,
    pub schema: RpcSchema
}

pub struct RPCHandler<T: ShareableTid<'static>> {
    // all RPC methods registered
    methods: HashMap<Cow<'static, str>, MethodHandler>,
    data: T,
    batch_limit: Option<usize>
}

tid! { impl<'a, T: 'static> TidAble<'a> for RPCHandler<T> where T: ShareableTid<'static> }

impl<T> RPCHandler<T>
where
    T: ShareableTid<'static>
{
    // Create a new RPC handler with optional batch limit
    pub fn new(data: T, limit: impl Into<Option<usize>>) -> Self {
        let mut handler = Self {
            methods: HashMap::new(),
            data,
            batch_limit: limit.into()
        };

        // Internally register the "schema" method to get all registered methods
        handler.register_method_no_params_custom_return::<Vec<RpcMethodInfo>>("schema", async_handler!(schema::<T>, single));
        handler.register_method_no_params("batch_limit", async_handler!(batch_limit::<T>, single));

        handler
    }

    // Create a new context with a reference to the RPC handler
    pub fn create_context<'ty, 'r>(&'r self) -> Context<'ty, 'r> {
        let mut context = Context::new();
        context.insert_ref(self);
        context
    }

    // Handle an RPC request from raw bytes
    pub async fn handle_request(&self, body: &[u8]) -> Result<Option<Value>, RpcResponseError> {
        let context = self.create_context();
        self.handle_request_with_context(context, body).await
    }

    // Handle an RPC request from raw bytes with a given context
    pub async fn handle_request_with_context<'ty, 'r>(&self, mut context: Context<'ty, 'r>, body: &[u8]) -> Result<Option<Value>, RpcResponseError> {
        let request: Value = serde_json::from_slice(body)
            .map_err(|_| RpcResponseError::new(None, InternalRpcError::ParseBodyError))?;

        Ok(match request {
            e @ Value::Object(_) => self.execute_method(&mut context, parse_request(e)?).await,
            Value::Array(requests) => {
                if self.batch_limit.is_some_and(|v| requests.len() > v) {
                    return Err(RpcResponseError::new(None, InternalRpcError::BatchLimitExceeded))
                }

                let mut responses = Vec::with_capacity(requests.len());
                for value in requests {
                    let request = parse_request(value)?;
                    if let Some(response) = self.execute_method(&mut context, request).await {
                        responses.push(response);
                    }
                }

                Some(Value::Array(responses))
            },
            _ => return Err(RpcResponseError::new(None, InternalRpcError::InvalidJSONRequest))
        })
    }

    pub fn has_method(&self, method_name: &str) -> bool {
        self.methods.contains_key(method_name)
    }

    // Execute an RPC method from a request
    // Returns None if there is no response expected (notification)
    pub async fn execute_method<'a, 'ty, 'r>(&'a self, context: &'a mut Context<'ty, 'r>, request: RpcRequest) -> Option<Value> {
        let response = request.id.is_some();
        match self.execute_method_internal(context, request).await {
            Ok(value) if response => Some(value),
            Err(e) if response => Some(e.to_json()),
            _ => None
        }
    }

    // Execute an RPC method from a request
    // it will dispatch to the correct handler based on the method name
    pub async fn execute_method_internal<'a, 'ty, 'r>(&'a self, context: &'a mut Context<'ty, 'r>, mut request: RpcRequest) -> Result<Value, RpcResponseError> {
        let key = Cow::Borrowed(request.method.as_str());
        let handler = self.methods.get(&key)
            .ok_or_else(|| RpcResponseError::new(request.id.clone(), InternalRpcError::MethodNotFound(request.method.clone())))?;

        trace!("executing '{}' RPC method", request.method);
        counter!("xelis_rpc_calls", "method" => request.method.clone()).increment(1);

        let params = request.params.take().unwrap_or(Value::Null);

        // insert the request id into the context
        context.insert(request.id.clone());

        let start = Instant::now();
        let result = (handler.handler)(context, params).await
            .map_err(|err| RpcResponseError::new(request.id.clone(), err))?;

        histogram!("xelis_rpc_calls_ms", "method" => request.method).record(start.elapsed().as_millis() as f64);

        Ok(json!({
            "jsonrpc": JSON_RPC_VERSION,
            "id": request.id,
            "result": result
        }))
    }

    // register a new RPC method handler
    pub fn register_method(&mut self, name: impl Into<Cow<'static, str>>, handler: MethodHandler) {
        let name = name.into();
        trace!("Registering RPC method: {}", name);
        let v = self.methods.insert(name.clone(), handler);
        assert!(v.is_none(), "RPC method '{}' is already registered", name);
    }

    // Register a method with parameters
    pub fn register_method_with_params<P, R>(
        &mut self,
        name: impl Into<Cow<'static, str>>,
        f: HandlerParams<P, R>,
    )
    where
        P: JsonSchema + DeserializeOwned + Send + 'static,
        R: JsonSchema + Serialize + Send + 'static,
    {
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
        name: impl Into<Cow<'static, str>>,
        f: HandlerParams<P, Value>,
    )
    where
        P: JsonSchema + DeserializeOwned + Send + 'static,
        R: JsonSchema + Serialize + Send + 'static,
    {
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
        name: impl Into<Cow<'static, str>>,
        f: HandlerNoParams<R>
    )
    where
        R: JsonSchema + Serialize + Send + 'static
    {
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
        name: impl Into<Cow<'static, str>>,
        f: HandlerNoParams<Value>
    )
    where
        R: JsonSchema + Serialize + Send + 'static
    {
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

    // Get a reference to the data associated with the RPC handler
    #[inline]
    pub fn get_data(&self) -> &T {
        &self.data
    }
}

// Built-in "schema" method to get all registered methods and their schemas
async fn schema<'a, T: ShareableTid<'static>>(context: &'a Context<'_, '_>) -> Result<Value, InternalRpcError> {
    let rpc_handler: &RPCHandler<T> = context.get()
        .ok_or(InternalRpcError::InternalError("RPCHandler not found in context"))?;

    let methods = rpc_handler.methods.iter()
        .map(|(name, handler)| RpcMethodInfo {
            name: Cow::Borrowed(name),
            schema: Cow::Borrowed(&handler.schema)
        }).collect::<Vec<_>>();

    Ok(json!(methods))
}

// Get the batch limit from the RPC handler, if any
// This is used to limit the number of requests in a batch to prevent DoS attacks
async fn batch_limit<'a, T: ShareableTid<'static>>(context: &'a Context<'_, '_>) -> Result<Option<usize>, InternalRpcError> {
    let rpc_handler: &RPCHandler<T> = context.get()
        .ok_or(InternalRpcError::InternalError("RPCHandler not found in context"))?;

    Ok(rpc_handler.batch_limit)
}

// Parse an RPC request from raw bytes
pub fn parse_request_from_bytes(body: &[u8]) -> Result<RpcRequest, RpcResponseError> {
    let request: RpcRequest = serde_json::from_slice(body)
        .map_err(|_| RpcResponseError::new(None, InternalRpcError::ParseBodyError))?;

    if request.jsonrpc != JSON_RPC_VERSION {
        return Err(RpcResponseError::new(request.id, InternalRpcError::InvalidVersion));
    }

    Ok(request)
}

// Parse an RPC request from a JSON value
pub fn parse_request(body: Value) -> Result<RpcRequest, RpcResponseError> {
    let request: RpcRequest = serde_json::from_value(body).map_err(|_| RpcResponseError::new(None, InternalRpcError::ParseBodyError))?;
    if request.jsonrpc != JSON_RPC_VERSION {
        return Err(RpcResponseError::new(request.id, InternalRpcError::InvalidVersion));
    }
    Ok(request)
}

// Parse parameters from a JSON value
// If the value is null, it is replaced with an empty object
pub fn parse_params<P: DeserializeOwned>(mut value: Value) -> Result<P, InternalRpcError> {
    if value.is_null() {
        value = Value::Object(Map::new());
    }

    serde_json::from_value(value)
        .map_err(|e| InternalRpcError::InvalidJSONParams(e))
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