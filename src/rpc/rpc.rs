use crate::{core::{blockchain::Blockchain, block::{Block, CompleteBlock}, serializer::Serializer, transaction::Transaction, storage::Storage}, crypto::{hash::Hash, address::Address}};
use super::{RpcError, RpcServer};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{json, Value};
use std::sync::Arc;
use log::{info, debug};

#[derive(Serialize)]
pub struct DataHash<T> {
    hash: Hash,
    #[serde(flatten)]
    data: T
}

#[derive(Serialize)]
pub enum BlockType {
    Sync,
    Side,
    Orphaned,
    Normal
}

#[derive(Serialize)]
pub struct BlockResponse<T> {
    topoheight: Option<u64>,
    block_type: BlockType,
    cumulative_difficulty: u64,
    #[serde(flatten)]
    data: DataHash<T>
}

#[derive(Serialize, Deserialize)]
pub struct GetBlockAtTopoHeightParams {
    topoheight: u64
}

#[derive(Serialize, Deserialize)]
pub struct GetBlocksAtHeightParams {
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

#[derive(Serialize, Deserialize)]
pub struct GetDagOrderParams {
    pub start_topoheight: Option<u64>,
    pub end_topoheight: Option<u64>
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

async fn get_block_type_for_block(blockchain: &Blockchain, storage: &Storage, hash: &Hash) -> Result<BlockType, RpcError> {
    Ok(if blockchain.is_block_orphaned_for_storage(storage, hash).await {
        BlockType::Orphaned
    } else if blockchain.is_block_sync(storage, hash).await? {
        BlockType::Sync
    } else if blockchain.is_side_block(storage, hash).await? {
        BlockType::Side
    } else {
        BlockType::Normal
    })
}

pub fn register_methods(server: &mut RpcServer) {
    info!("Registering RPC methods...");
    server.register_method("get_height", method!(get_height));
    server.register_method("get_topoheight", method!(get_topoheight));
    server.register_method("get_stableheight", method!(get_stableheight));
    server.register_method("get_block_template", method!(get_block_template));
    server.register_method("get_block_at_topoheight", method!(get_block_at_topoheight));
    server.register_method("get_blocks_at_height", method!(get_blocks_at_height));
    server.register_method("get_block_by_hash", method!(get_block_by_hash));
    server.register_method("get_top_block", method!(get_top_block));
    server.register_method("submit_block", method!(submit_block));
    server.register_method("get_account", method!(get_account));
    server.register_method("count_accounts", method!(count_accounts));
    server.register_method("count_transactions", method!(count_transactions));
    server.register_method("submit_transaction", method!(submit_transaction));
    server.register_method("p2p_status", method!(p2p_status));
    server.register_method("get_mempool", method!(get_mempool));
    server.register_method("get_tips", method!(get_tips));
    server.register_method("get_dag_order", method!(get_dag_order));
}

async fn get_height(blockchain: Arc<Blockchain>, body: Value) -> Result<Value, RpcError> {
    if body != Value::Null {
        return Err(RpcError::UnexpectedParams)
    }
    Ok(json!(blockchain.get_height()))
}

async fn get_topoheight(blockchain: Arc<Blockchain>, body: Value) -> Result<Value, RpcError> {
    if body != Value::Null {
        return Err(RpcError::UnexpectedParams)
    }
    Ok(json!(blockchain.get_topo_height()))
}

async fn get_stableheight(blockchain: Arc<Blockchain>, body: Value) -> Result<Value, RpcError> {
    if body != Value::Null {
        return Err(RpcError::UnexpectedParams)
    }

    Ok(json!(blockchain.get_stable_height().await?))
}

async fn get_block_at_topoheight(blockchain: Arc<Blockchain>, body: Value) -> Result<Value, RpcError> {
    let params: GetBlockAtTopoHeightParams = parse_params(body)?;
    let storage = blockchain.get_storage().read().await;
    let hash = storage.get_hash_at_topo_height(params.topoheight).await?;
    let block = storage.get_complete_block(&hash).await?;
    let cumulative_difficulty = storage.get_cumulative_difficulty_for_block(&hash).await?;
    Ok(json!(BlockResponse { topoheight: Some(params.topoheight), block_type: get_block_type_for_block(&blockchain, &storage, &hash).await?, cumulative_difficulty, data: DataHash { hash, data: block } }))
}

async fn get_block_by_hash(blockchain: Arc<Blockchain>, body: Value) -> Result<Value, RpcError> {
    let params: GetBlockByHashParams = parse_params(body)?;
    let storage = blockchain.get_storage().read().await;
    let block = storage.get_block_by_hash(&params.hash).await?;
    let topoheight = if storage.is_block_topological_ordered(&params.hash).await {
        Some(storage.get_topo_height_for_hash(&params.hash).await?)
    } else {
        None
    };
    let cumulative_difficulty = storage.get_cumulative_difficulty_for_block(&params.hash).await?;
    Ok(json!(BlockResponse { topoheight, block_type: get_block_type_for_block(&blockchain, &storage, &params.hash).await?, cumulative_difficulty, data: DataHash { hash: params.hash, data: block } }))
}

async fn get_top_block(blockchain: Arc<Blockchain>, body: Value) -> Result<Value, RpcError> {
    if body != Value::Null {
        return Err(RpcError::UnexpectedParams)
    }
    let storage = blockchain.get_storage().read().await;
    let hash = blockchain.get_top_block_hash_for_storage(&storage).await?;
    let block = storage.get_complete_block(&hash).await?;
    let topoheight = if storage.is_block_topological_ordered(&hash).await {
        Some(storage.get_topo_height_for_hash(&hash).await?)
    } else {
        None
    };
    let cumulative_difficulty = storage.get_cumulative_difficulty_for_block(&hash).await?;
    Ok(json!(BlockResponse { topoheight, block_type: get_block_type_for_block(&blockchain, &storage, &hash).await?, cumulative_difficulty, data: DataHash { hash, data: block } }))
}

async fn get_block_template(blockchain: Arc<Blockchain>, body: Value) -> Result<Value, RpcError> {
    let params: GetBlockTemplateParams = parse_params(body)?;
    if !params.address.is_normal() {
        return Err(RpcError::ExpectedNormalAddress)
    }
    let storage = blockchain.get_storage().read().await;
    let block = blockchain.get_block_template_for_storage(&storage, params.address.to_public_key()).await?;
    let difficulty = blockchain.get_difficulty_at_tips(&storage, block.get_tips()).await?;
    Ok(json!(GetBlockTemplateResult { template: block.to_hex(), difficulty }))
}

async fn submit_block(blockchain: Arc<Blockchain>, body: Value) -> Result<Value, RpcError> {
    let params: SubmitBlockParams = parse_params(body)?;
    let block = Block::from_hex(params.block_template)?;
     // TODO add block hashing blob on block template
    let complete_block = blockchain.build_complete_block_from_block(block).await?;
    blockchain.add_new_block(complete_block, true).await?;
    Ok(json!(true))
}

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
    let mut transactions: Vec<DataHash<Arc<Transaction>>> = Vec::new();
    for tx in mempool.get_sorted_txs() {
        let transaction = mempool.view_tx(tx.get_hash())?;
        transactions.push(DataHash { hash: tx.get_hash().clone(), data: transaction });
    }

    Ok(json!(transactions))
}

async fn get_blocks_at_height(blockchain: Arc<Blockchain>, body: Value) -> Result<Value, RpcError> {
    let params: GetBlocksAtHeightParams = parse_params(body)?;
    let storage = blockchain.get_storage().read().await;

    let mut blocks: Vec<BlockResponse<CompleteBlock>> = Vec::new();
    for hash in storage.get_blocks_at_height(params.height).await? {
        let topoheight = if storage.is_block_topological_ordered(&hash).await {
            Some(storage.get_topo_height_for_hash(&hash).await?)
        } else {
            None
        };

        let block = storage.get_complete_block(&hash).await?;
        let cumulative_difficulty = storage.get_cumulative_difficulty_for_block(&hash).await?;
        blocks.push(BlockResponse { topoheight, block_type: get_block_type_for_block(&blockchain, &storage, &hash).await?, cumulative_difficulty, data: DataHash { hash, data: block } })
    }
    Ok(json!(blocks))
}

async fn get_tips(blockchain: Arc<Blockchain>, body: Value) -> Result<Value, RpcError> {
    if body != Value::Null {
        return Err(RpcError::UnexpectedParams)
    }
    let storage = blockchain.get_storage().read().await;
    let tips = storage.get_tips().await?;
    Ok(json!(tips))
}

const MAX_DAG_ORDER: u64 = 64;
// get dag order based on params
// if no params found, get order of last 64 blocks
async fn get_dag_order(blockchain: Arc<Blockchain>, body: Value) -> Result<Value, RpcError> {
    let params: GetDagOrderParams = parse_params(body)?;

    let current_topoheight = blockchain.get_topo_height();
    let start_topoheight = params.start_topoheight.unwrap_or_else(|| {
        if params.end_topoheight.is_none() && current_topoheight > MAX_DAG_ORDER {
            current_topoheight - MAX_DAG_ORDER
        } else {
            0
        }
    });

    let end_topoheight = params.end_topoheight.unwrap_or(current_topoheight);
    if end_topoheight < start_topoheight || end_topoheight > current_topoheight {
        debug!("get dag order range: start = {}, end = {}, max = {}", start_topoheight, end_topoheight, current_topoheight);
        return Err(RpcError::InvalidRequest)
    }

    let count = end_topoheight - start_topoheight;
    if count > MAX_DAG_ORDER { // only retrieve max 64 blocks hash per request
        debug!("get dag order requested count: {}", count);
        return Err(RpcError::InvalidRequest) 
    }

    let storage = blockchain.get_storage().read().await;
    let mut order = Vec::with_capacity(count as usize);
    for i in start_topoheight..=end_topoheight {
        let hash = storage.get_hash_at_topo_height(i).await?;
        order.push(hash);
    }

    Ok(json!(order))
}