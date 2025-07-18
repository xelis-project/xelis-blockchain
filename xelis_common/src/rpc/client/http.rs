use reqwest::Client as HttpClient;
use serde::{
    Serialize,
    de::DeserializeOwned
};
use super::{
    JsonRPCResult, JsonRPCErrorResponse, JsonRPCError,
    JSON_RPC_VERSION, PARSE_ERROR_CODE, INVALID_REQUEST_CODE,
    METHOD_NOT_FOUND_CODE, INVALID_PARAMS_CODE, INTERNAL_ERROR_CODE
};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};

pub struct JsonRPCClient {
    http: HttpClient,
    target: String,
    count: AtomicUsize,
}

impl JsonRPCClient {
    pub fn new(target: String) -> Self {
        JsonRPCClient {
            http: HttpClient::new(),
            target,
            count: AtomicUsize::new(0),
        }
    }

    pub async fn call<R: DeserializeOwned>(&self, method: &str) -> JsonRPCResult<R> {
        let id = self.count.fetch_add(1, Ordering::SeqCst);
        self.send(json!({
            "jsonrpc": JSON_RPC_VERSION,
            "method": method,
            "id": id
        })).await
    }

    pub async fn call_with<P, R>(&self, method: &str, params: &P) -> JsonRPCResult<R>
        where P: Serialize + Sized, R: DeserializeOwned
    {
        let id = self.count.fetch_add(1, Ordering::SeqCst);
        self.send(json!({
            "jsonrpc": JSON_RPC_VERSION,
            "method": method,
            "id": id,
            "params": params
        })).await
    }

    pub async fn notify(&self, method: &str) -> JsonRPCResult<()> {
        self.http.post(&self.target)
            .json(&json!({
                "jsonrpc": JSON_RPC_VERSION,
                "method": method
            }))
            .send().await?;
        Ok(())
    }

    pub async fn notify_with<P>(&self, method: &str, params: P) -> JsonRPCResult<()>
        where P: Serialize + Sized
    {
        self.http
            .post(&self.target)
            .json(&json!({
                "jsonrpc": JSON_RPC_VERSION,
                "method": method,
                "params": &params
            }))
            .send().await?;
        Ok(())
    }

    pub async fn send<R: DeserializeOwned>(&self, value: Value) -> JsonRPCResult<R> {
        let mut response: Value = self.http.post(&self.target)
            .json(&value)
            .send().await?
            .json().await?;

        if let Some(error) = response.get_mut("error") {
            let error: JsonRPCErrorResponse = serde_json::from_value(error.take())?;
            let data = match error.data {
                Some(content) => Some(serde_json::to_string_pretty(&content)?),
                None => None,
            };

            return Err(match error.code {
                PARSE_ERROR_CODE => JsonRPCError::ParseError,
                INVALID_REQUEST_CODE => JsonRPCError::InvalidRequest,
                METHOD_NOT_FOUND_CODE => JsonRPCError::MethodNotFound,
                INVALID_PARAMS_CODE => JsonRPCError::InvalidParams,
                INTERNAL_ERROR_CODE => JsonRPCError::InternalError {
                    message: error.message.clone(),
                    data,
                },
                code => JsonRPCError::ServerError {
                    code,
                    message: error.message.clone(),
                    data,
                },
            });
        }

        Ok(serde_json::from_value(
            response
                .get_mut("result")
                .ok_or(JsonRPCError::MissingResult)?
                .take(),
        )?)
    }
}