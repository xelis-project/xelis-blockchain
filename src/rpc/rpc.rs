use crate::{core::blockchain::Blockchain, crypto::{key::PublicKey, hash::Hash}};
use super::{RpcError, RpcServer};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{json, Value};
use std::sync::Arc;
use log::info;


#[derive(Serialize, Deserialize)]
pub struct GetBlockAtHeightParams {
    height: u64
}

#[derive(Serialize, Deserialize)]
pub struct GetBlockByHashParams {
    hash: Hash
}

#[derive(Serialize, Deserialize)]
pub struct GetBlockTemplateParams {
    address: String
}

macro_rules! method {
    ($func: expr) => {
        Box::new(move |a, b| {
          Box::pin($func(a, b))
        })
    };
}

fn parse_params<P: DeserializeOwned>(value: Value) -> Result<P, RpcError> {
    serde_json::from_value(value).map_err(|e| RpcError::InvalidParams(e))
}

pub fn register_methods(server: &mut RpcServer) {
    info!("Registering RPC methods...");
    server.register_method("get_height", method!(get_height));
    server.register_method("get_block_template", method!(get_block_template));
    server.register_method("get_block_at_height", method!(get_block_at_height));
    server.register_method("get_block_by_hash", method!(get_block_by_hash));
}

async fn get_height(blockchain: Arc<Blockchain>, body: Value) -> Result<Value, RpcError> {
    if body != Value::Null {
        return Err(RpcError::UnexpectedParams)
    }
    Ok(json!(blockchain.get_height()))
}

async fn get_block_at_height(blockchain: Arc<Blockchain>, body: Value) -> Result<Value, RpcError> {
    let params: GetBlockAtHeightParams = parse_params(body)?;
    let storage = blockchain.get_storage().lock().await;
    let block = storage.get_block_at_height(params.height)?;
    Ok(json!(block))
}

async fn get_block_by_hash(blockchain: Arc<Blockchain>, body: Value) -> Result<Value, RpcError> {
    let params: GetBlockByHashParams = parse_params(body)?;
    let storage = blockchain.get_storage().lock().await;
    let block = storage.get_block_by_hash(&params.hash)?;
    Ok(json!(block))
}

async fn get_block_template(blockchain: Arc<Blockchain>, body: Value) -> Result<Value, RpcError> {
    let params: GetBlockTemplateParams = parse_params(body)?;
    let address = PublicKey::from_address(&params.address)?;
    let block = blockchain.get_block_template(address).await?;
    Ok(json!(block))
}