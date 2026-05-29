use std::borrow::Cow;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use runtime_context::tid;

pub const JSON_RPC_VERSION: &str = "2.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Id {
    String(String),
    Number(usize),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub id: Option<Id>,
    pub method: String,
    pub params: Option<Value>
}

tid!(Id);
tid!(RpcRequest);

#[derive(Serialize)]
pub struct RpcResponse<'a> {
    pub jsonrpc: &'a str,
    pub id: Cow<'a, Option<Id>>,
    pub result: Cow<'a, Value>
}

impl<'a> RpcResponse<'a> {
    pub fn new(id: Cow<'a, Option<Id>>, result: Cow<'a, Value>) -> Self {
        Self {
            jsonrpc: JSON_RPC_VERSION,
            id,
            result
        }
    }
}
