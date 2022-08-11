use crate::{core::{blockchain::Blockchain, block::Block, serializer::Serializer, transaction::Transaction}, crypto::{hash::Hash, address::Address}};
use super::{RpcError, RpcServer};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{json, Value};
use std::sync::Arc;
use log::info;

#[derive(Serialize)]
pub struct DataHash<T> {
    hash: Hash,
    #[serde(flatten)]
    data: T
}

#[derive(Serialize, Deserialize)]
pub struct GetBlockAtHeightParams {
    height: u64
}

#[derive(Serialize, Deserialize)]
pub struct GetBlockByHashParams {
    hash: Hash
}

#[derive(Serialize, Deserialize)]
pub struct GetBlockTemplateParams<'a> {
    pub address: Address<'a>
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

#[derive(Serialize, Deserialize)]
pub struct GetMessagesParams<'a> {
    pub address: Address<'a>,
    pub from: Option<Address<'a>>
}

#[derive(Serialize, Deserialize)]
pub struct GetAccountParams<'a> {
    pub address: Address<'a>
}

#[derive(Serialize, Deserialize)]
pub struct SubmitTransactionParams {
    pub data: String // should be in hex format
}

#[derive(Serialize, Deserialize)]
pub struct P2pStatusResult {
    pub peer_count: usize,
    pub max_peers: usize,
    pub tag: Option<String>,
    pub our_height: u64,
    pub best_height: u64,
    pub peer_id: u64
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
    server.register_method("get_top_block", method!(get_top_block));
    server.register_method("submit_block", method!(submit_block));
    //server.register_method("get_messages", method!(get_messages));
    server.register_method("get_account", method!(get_account));
    server.register_method("count_accounts", method!(count_accounts));
    server.register_method("count_transactions", method!(count_transactions));
    server.register_method("submit_transaction", method!(submit_transaction));
    server.register_method("p2p_status", method!(p2p_status));
    server.register_method("get_mempool", method!(get_mempool));
    // TODO only in debug mode
    server.register_method("is_chain_valid", method!(is_chain_valid));
}

async fn get_height(blockchain: Arc<Blockchain>, body: Value) -> Result<Value, RpcError> {
    if body != Value::Null {
        return Err(RpcError::UnexpectedParams)
    }
    Ok(json!(blockchain.get_height()))
}

async fn get_block_at_height(blockchain: Arc<Blockchain>, body: Value) -> Result<Value, RpcError> {
    let params: GetBlockAtHeightParams = parse_params(body)?;
    let storage = blockchain.get_storage().read().await;
    let metadata = storage.get_block_metadata(params.height).await?;
    let block = storage.get_complete_block(metadata.get_hash()).await?;
    Ok(json!(DataHash { hash: metadata.get_hash().clone(), data: block }))
}

async fn get_block_by_hash(blockchain: Arc<Blockchain>, body: Value) -> Result<Value, RpcError> {
    let params: GetBlockByHashParams = parse_params(body)?;
    let storage = blockchain.get_storage().read().await;
    let block = storage.get_block_by_hash(&params.hash).await?;
    Ok(json!(DataHash { hash: params.hash, data: block }))
}

async fn get_top_block(blockchain: Arc<Blockchain>, body: Value) -> Result<Value, RpcError> {
    if body != Value::Null {
        return Err(RpcError::UnexpectedParams)
    }
    let storage = blockchain.get_storage().read().await;
    let hash = storage.get_top_block_hash()?;
    let block = storage.get_complete_block(&hash).await?;
    Ok(json!(DataHash { hash, data: block }))
}

async fn get_block_template(blockchain: Arc<Blockchain>, body: Value) -> Result<Value, RpcError> {
    let params: GetBlockTemplateParams = parse_params(body)?;
    if !params.address.is_normal() {
        return Err(RpcError::ExpectedNormalAddress)
    }
    let block = blockchain.get_block_template(params.address.to_public_key()).await?;
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

/*
async fn get_messages(blockchain: Arc<Blockchain>, body: Value) -> Result<Value, RpcError> {
    let params: GetMessagesParams = parse_params(body)?;
    if !params.address.is_normal() {
        return Err(RpcError::ExpectedNormalAddress)
    }
    // TODO
    let messages: Vec<&dyn MessageData> = Vec::new();
    todo!("xelis messages") //Ok(json!(messages))
}
*/

async fn get_account(blockchain: Arc<Blockchain>, body: Value) -> Result<Value, RpcError> {
    let params: GetAccountParams = parse_params(body)?;
    let storage = blockchain.get_storage().read().await;
    let account = storage.get_account(params.address.get_public_key()).await?;
    Ok(json!(account))
}

async fn count_accounts(blockchain: Arc<Blockchain>, body: Value) -> Result<Value, RpcError> {
    if body != Value::Null {
        return Err(RpcError::UnexpectedParams)
    }
    let storage = blockchain.get_storage().read().await;
    Ok(json!(storage.count_accounts()))
}

async fn count_transactions(blockchain: Arc<Blockchain>, body: Value) -> Result<Value, RpcError> {
    if body != Value::Null {
        return Err(RpcError::UnexpectedParams)
    }
    let storage = blockchain.get_storage().read().await;
    Ok(json!(storage.count_transactions()))
}

async fn submit_transaction(blockchain: Arc<Blockchain>, body: Value) -> Result<Value, RpcError> {
    let params: SubmitTransactionParams = parse_params(body)?;
    let transaction = Transaction::from_hex(params.data)?;
    blockchain.add_tx_to_mempool(transaction, true).await?;
    Ok(json!(true))
}

async fn p2p_status(blockchain: Arc<Blockchain>, body: Value) -> Result<Value, RpcError> {
    if body != Value::Null {
        return Err(RpcError::UnexpectedParams)
    }

    let p2p = blockchain.get_p2p().lock().await;
    match p2p.as_ref() {
        Some(p2p) => {
            let peer_count = p2p.get_peer_count().await;
            let tag = p2p.get_tag();
            let peer_id = p2p.get_peer_id();
            let best_height = p2p.get_best_height().await;
            let max_peers = p2p.get_max_peers();

            let our_height = blockchain.get_height();

            Ok(json!(P2pStatusResult {
                peer_count,
                tag: tag.clone(),
                peer_id,
                our_height,
                best_height,
                max_peers
            }))
        },
        None => return Err(RpcError::NoP2p)
    }
}

async fn get_mempool(blockchain: Arc<Blockchain>, body: Value) -> Result<Value, RpcError> {
    if body != Value::Null {
        return Err(RpcError::UnexpectedParams)
    }

    let mempool = blockchain.get_mempool().read().await;
    let mut transactions = Vec::new();
    for tx in mempool.get_sorted_txs() {
        let transaction = mempool.view_tx(tx.get_hash())?;
        transactions.push(transaction);
    }

    Ok(json!(transactions))
}

async fn is_chain_valid(blockchain: Arc<Blockchain>, body: Value) -> Result<Value, RpcError> {
    if body != Value::Null {
        return Err(RpcError::UnexpectedParams)
    }

    blockchain.check_validity().await?;
    Ok(json!(true))
}