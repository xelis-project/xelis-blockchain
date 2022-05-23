use crate::{core::{blockchain::Blockchain, block::Block, serializer::Serializer}, crypto::{key::PublicKey, hash::Hash}};
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
    pub address: String
}

#[derive(Serialize, Deserialize)]
pub struct GetBlockTemplateResult {
    pub template: String,
    pub difficulty: u64
}

#[derive(Serialize, Deserialize)]
pub struct SubmitBlockParams {
    pub block_template: String, // hex: represent the BlockHeader (Block)
    pub block_hashing_blob: String // hex
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
    server.register_method("submit_block", method!(submit_block));
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
    Ok(json!(GetBlockTemplateResult { template: block.to_hex(), difficulty: blockchain.get_difficulty() }))
}

async fn submit_block(blockchain: Arc<Blockchain>, body: Value) -> Result<Value, RpcError> {
    let params: SubmitBlockParams = parse_params(body)?;
    let block = Block::from_hex(params.block_template)?;
     // TODO add block hashing blob on block template
    let complete_block = blockchain.build_complete_block_from_block(block).await?;
    blockchain.add_new_block(complete_block, true).await?;
    Ok(json!(true))
}