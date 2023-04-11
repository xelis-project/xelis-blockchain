use std::sync::Arc;

use log::info;
use xelis_common::{rpc_server::{RPCHandler, InternalRpcError}, config::VERSION, async_handler};
use serde_json::{Value, json};
use crate::wallet::Wallet;

pub fn register_methods(handler: &mut RPCHandler<Arc<Wallet>>) {
    info!("Registering RPC methods...");
    handler.register_method("version", async_handler!(version));
}

async fn version(_: Arc<Wallet>, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }
    Ok(json!(VERSION))
}