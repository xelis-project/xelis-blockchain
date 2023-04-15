use crate::core::{blockchain::Blockchain, storage::Storage, error::BlockchainError};
use super::{InternalRpcError, ApiError};
use anyhow::Context;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use xelis_common::{
    api::daemon::{
        BlockType,
        BlockResponse,
        DataHash,
        GetBlockAtTopoHeightParams,
        GetBlockByHashParams,
        GetBlockTemplateParams,
        GetBlockTemplateResult,
        SubmitBlockParams,
        GetBalanceParams,
        GetNonceParams,
        SubmitTransactionParams,
        GetTransactionParams,
        P2pStatusResult,
        GetBlocksAtHeightParams,
        GetRangeParams, GetBalanceAtTopoHeightParams, GetLastBalanceResult, GetInfoResult, GetTopBlockParams, GetTransactionsParams, TransactionResponse
    },
    async_handler,
    serializer::Serializer,
    transaction::Transaction,
    crypto::hash::Hash,
    block::{BlockHeader, Block}, config::{BLOCK_TIME_MILLIS, VERSION}, immutable::Immutable, rpc_server::RPCHandler,
};
use std::{sync::Arc, borrow::Cow};
use log::{info, debug};

fn parse_params<P: DeserializeOwned>(value: Value) -> Result<P, InternalRpcError> {
    serde_json::from_value(value).map_err(|e| InternalRpcError::InvalidParams(e))
}

pub async fn get_block_type_for_block<S: Storage>(blockchain: &Blockchain<S>, storage: &S, hash: &Hash) -> Result<BlockType, InternalRpcError> {
    Ok(if blockchain.is_block_orphaned_for_storage(storage, hash).await {
        BlockType::Orphaned
    } else if blockchain.is_block_sync(storage, hash).await.context("Error while checking if block is sync")? {
        BlockType::Sync
    } else if blockchain.is_side_block(storage, hash).await.context("Error while checking if block is side")? {
        BlockType::Side
    } else {
        BlockType::Normal
    })
}

pub async fn get_block_response_for_hash<S: Storage>(blockchain: &Blockchain<S>, storage: &S, hash: Hash, include_txs: bool) -> Result<Value, InternalRpcError> {
    let (topoheight, supply, reward) = if  storage.is_block_topological_ordered(&hash).await {
        (
            Some(storage.get_topo_height_for_hash(&hash).await.context("Error while retrieving topo height")?),
            Some( storage.get_supply_for_block_hash(&hash).context("Error while retrieving supply")?),
            Some(storage.get_block_reward(&hash).context("Error while retrieving block reward")?),
        )
    } else {
        (
            None,
            None,
            None,
        )
    };

    let block_type = get_block_type_for_block(&blockchain, &storage, &hash).await?;
    let cumulative_difficulty = storage.get_cumulative_difficulty_for_block_hash(&hash).await.context("Error while retrieving cumulative difficulty")?;
    let difficulty = storage.get_difficulty_for_block_hash(&hash).await.context("Error while retrieving difficulty")?;
    let block = storage.get_block(&hash).await.context("Error while retrieving block")?;
    let total_size_in_bytes = block.size();
    let mut total_fees = 0;
    for tx in block.get_transactions() {
        total_fees += tx.get_fee();
    }

    let value: Value = if include_txs {
        let data: DataHash<'_, Block> = DataHash { hash: Cow::Borrowed(&hash), data: Cow::Owned(block) };
        json!(BlockResponse { topoheight, block_type, cumulative_difficulty, difficulty, supply, reward, total_fees, total_size_in_bytes, data })
    } else {
        let data: DataHash<'_, Arc<BlockHeader>> = DataHash { hash: Cow::Borrowed(&hash), data: Cow::Owned(block.to_header()) };
        json!(BlockResponse { topoheight, block_type, cumulative_difficulty, difficulty, supply, reward, total_fees, total_size_in_bytes, data })
    };

    Ok(value)
}

pub async fn get_transaction_response<S: Storage>(storage: &S, tx: &Arc<Transaction>, hash: &Hash) -> Result<Value, InternalRpcError> {
    let blocks = if storage.has_tx_blocks(hash).context("Error while checking if tx in included in blocks")? {
        Some(storage.get_blocks_for_tx(hash).context("Error while retrieving in which blocks its included")?)
    } else {
        None
    };

    let data: DataHash<'_, Arc<Transaction>> = DataHash { hash: Cow::Borrowed(&hash), data: Cow::Borrowed(tx) };
    let executed_in_block = storage.get_tx_executed_in_block(hash).ok();
    Ok(json!(TransactionResponse { blocks, executed_in_block, data }))
}

pub async fn get_transaction_response_for_hash<S: Storage>(storage: &S, hash: &Hash) -> Result<Value, InternalRpcError> {
    let tx = storage.get_transaction(hash).await.context("Error while retrieving transaction")?;
    get_transaction_response(storage, &tx, hash).await
}

pub fn register_methods<S: Storage>(handler: &mut RPCHandler<Arc<Blockchain<S>>>) {
    info!("Registering RPC methods...");
    handler.register_method("get_version", async_handler!(version));
    handler.register_method("get_height", async_handler!(get_height));
    handler.register_method("get_topoheight", async_handler!(get_topoheight));
    handler.register_method("get_stableheight", async_handler!(get_stableheight));
    handler.register_method("get_block_template", async_handler!(get_block_template));
    handler.register_method("get_block_at_topoheight", async_handler!(get_block_at_topoheight));
    handler.register_method("get_blocks_at_height", async_handler!(get_blocks_at_height));
    handler.register_method("get_block_by_hash", async_handler!(get_block_by_hash));
    handler.register_method("get_top_block", async_handler!(get_top_block));
    handler.register_method("submit_block", async_handler!(submit_block));
    handler.register_method("get_last_balance", async_handler!(get_last_balance));
    handler.register_method("get_balance_at_topoheight", async_handler!(get_balance_at_topoheight));
    handler.register_method("get_info", async_handler!(get_info));
    handler.register_method("get_nonce", async_handler!(get_nonce));
    handler.register_method("get_assets", async_handler!(get_assets));
    handler.register_method("count_transactions", async_handler!(count_transactions));
    handler.register_method("submit_transaction", async_handler!(submit_transaction));
    handler.register_method("get_transaction", async_handler!(get_transaction));
    handler.register_method("p2p_status", async_handler!(p2p_status));
    handler.register_method("get_mempool", async_handler!(get_mempool));
    handler.register_method("get_tips", async_handler!(get_tips));
    handler.register_method("get_dag_order", async_handler!(get_dag_order));
    handler.register_method("get_blocks", async_handler!(get_blocks));
    handler.register_method("get_transactions", async_handler!(get_transactions));

}

async fn version<S: Storage>(_: Arc<Blockchain<S>>, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }
    Ok(json!(VERSION))
}

async fn get_height<S: Storage>(blockchain: Arc<Blockchain<S>>, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }
    Ok(json!(blockchain.get_height()))
}

async fn get_topoheight<S: Storage>(blockchain: Arc<Blockchain<S>>, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }
    Ok(json!(blockchain.get_topo_height()))
}

async fn get_stableheight<S: Storage>(blockchain: Arc<Blockchain<S>>, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }

    Ok(json!(blockchain.get_stable_height()))
}

async fn get_block_at_topoheight<S: Storage>(blockchain: Arc<Blockchain<S>>, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetBlockAtTopoHeightParams = parse_params(body)?;
    let storage = blockchain.get_storage().read().await;
    let hash = storage.get_hash_at_topo_height(params.topoheight).await.context("Error while retrieving hash at topo height")?;
    get_block_response_for_hash(&blockchain, &storage, hash, params.include_txs).await
}

async fn get_block_by_hash<S: Storage>(blockchain: Arc<Blockchain<S>>, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetBlockByHashParams = parse_params(body)?;
    let storage = blockchain.get_storage().read().await;
    get_block_response_for_hash(&blockchain, &storage, params.hash.into_owned(), params.include_txs).await
}

async fn get_top_block<S: Storage>(blockchain: Arc<Blockchain<S>>, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetTopBlockParams = parse_params(body)?;
    let storage = blockchain.get_storage().read().await;
    let hash = blockchain.get_top_block_hash_for_storage(&storage).await.context("Error while retrieving top block hash")?;
    get_block_response_for_hash(&blockchain, &storage, hash, params.include_txs).await
}

async fn get_block_template<S: Storage>(blockchain: Arc<Blockchain<S>>, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetBlockTemplateParams = parse_params(body)?;
    if !params.address.is_normal() {
        return Err(InternalRpcError::AnyError(ApiError::ExpectedNormalAddress.into()))
    }

    if params.address.is_mainnet() != blockchain.get_network().is_mainnet() {
        return Err(InternalRpcError::AnyError(BlockchainError::InvalidNetwork.into()))
    }

    let storage = blockchain.get_storage().read().await;
    let block = blockchain.get_block_template_for_storage(&storage, params.address.into_owned().to_public_key()).await.context("Error while retrieving block template")?;
    let difficulty = blockchain.get_difficulty_at_tips(&*storage, block.get_tips()).await.context("Error while retrieving difficulty at tips")?;
    let height = block.height;
    Ok(json!(GetBlockTemplateResult { template: block.to_hex(), height, difficulty }))
}

async fn submit_block<S: Storage>(blockchain: Arc<Blockchain<S>>, body: Value) -> Result<Value, InternalRpcError> {
    let params: SubmitBlockParams = parse_params(body)?;
    let header = BlockHeader::from_hex(params.block_template)?;
    // TODO add block hashing blob on block template
    let block = blockchain.build_block_from_header(Immutable::Owned(header)).await.context("Error while building block from header")?;
    blockchain.add_new_block(block, true).await.context("Error while adding new block to chain")?;
    Ok(json!(true))
}

async fn get_last_balance<S: Storage>(blockchain: Arc<Blockchain<S>>, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetBalanceParams = parse_params(body)?;
    if params.address.is_mainnet() != blockchain.get_network().is_mainnet() {
        return Err(InternalRpcError::AnyError(BlockchainError::InvalidNetwork.into()))
    }

    let storage = blockchain.get_storage().read().await;
    let (topoheight, balance) = storage.get_last_balance(params.address.get_public_key(), &params.asset).await.context("Error while retrieving last balance")?;
    Ok(json!(GetLastBalanceResult {
        balance,
        topoheight
    }))
}

async fn get_info<S: Storage>(blockchain: Arc<Blockchain<S>>, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }

    let height = blockchain.get_height();
    let topoheight = blockchain.get_topo_height();
    let stableheight = blockchain.get_stable_height();
    let (top_hash, native_supply) = {
        let storage = blockchain.get_storage().read().await;
        let top_hash = storage.get_hash_at_topo_height(topoheight).await.context("Error while retrieving hash at topo height")?;
        let supply = storage.get_supply_for_block_hash(&top_hash).context("Error while supply for hash")?;
        (top_hash, supply)
    };
    let difficulty = blockchain.get_difficulty();
    let block_time_target = BLOCK_TIME_MILLIS;
    let mempool_size = blockchain.get_mempool_size().await;
    let version = VERSION.into();
    let network = *blockchain.get_network();

    Ok(json!(GetInfoResult {
        height,
        topoheight,
        stableheight,
        top_hash,
        native_supply,
        difficulty,
        block_time_target,
        mempool_size,
        version,
        network
    }))
}

async fn get_balance_at_topoheight<S: Storage>(blockchain: Arc<Blockchain<S>>, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetBalanceAtTopoHeightParams = parse_params(body)?;
    let topoheight = blockchain.get_topo_height();
    if params.topoheight > topoheight {
        return Err(InternalRpcError::UnexpectedParams).context("Topoheight cannot be greater than current chain topoheight")?
    }

    if params.address.is_mainnet() != blockchain.get_network().is_mainnet() {
        return Err(InternalRpcError::AnyError(BlockchainError::InvalidNetwork.into()))
    }

    let storage = blockchain.get_storage().read().await;
    let balance = storage.get_balance_at_exact_topoheight(params.address.get_public_key(), &params.asset, params.topoheight).await.context("Error while retrieving balance at exact topo height")?;
    Ok(json!(balance))
}

async fn get_nonce<S: Storage>(blockchain: Arc<Blockchain<S>>, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetNonceParams = parse_params(body)?;
    if params.address.is_mainnet() != blockchain.get_network().is_mainnet() {
        return Err(InternalRpcError::AnyError(BlockchainError::InvalidNetwork.into()))
    }

    let storage = blockchain.get_storage().read().await;
    let nonce = storage.get_nonce(params.address.get_public_key()).await.context("Error while retrieving nonce for account")?;
    Ok(json!(nonce))
}

// TODO Rate limiter
async fn get_assets<S: Storage>(blockchain: Arc<Blockchain<S>>, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }

    let storage = blockchain.get_storage().read().await;
    let assets = storage.get_assets().await.context("Error while retrieving registered assets")?;
    Ok(json!(assets))
}

// TODO Rate limiter
async fn count_transactions<S: Storage>(blockchain: Arc<Blockchain<S>>, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }
    let storage = blockchain.get_storage().read().await;
    Ok(json!(storage.count_transactions()))
}

async fn submit_transaction<S: Storage>(blockchain: Arc<Blockchain<S>>, body: Value) -> Result<Value, InternalRpcError> {
    let params: SubmitTransactionParams = parse_params(body)?;
    let transaction = Transaction::from_hex(params.data)?;
    blockchain.add_tx_to_mempool(transaction, true).await.context("Error while adding tx to mempool")?;
    Ok(json!(true))
}

async fn get_transaction<S: Storage>(blockchain: Arc<Blockchain<S>>, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetTransactionParams = parse_params(body)?;
    let storage = blockchain.get_storage().read().await;
    get_transaction_response_for_hash(&*storage, &params.hash).await
}

async fn p2p_status<S: Storage>(blockchain: Arc<Blockchain<S>>, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }

    let p2p = blockchain.get_p2p().lock().await;
    match p2p.as_ref() {
        Some(p2p) => {
            let peer_count = p2p.get_peer_count().await;
            let tag = p2p.get_tag();
            let peer_id = p2p.get_peer_id();
            let best_topoheight = p2p.get_best_topoheight().await;
            let max_peers = p2p.get_max_peers();
            let our_topoheight = blockchain.get_topo_height();

            Ok(json!(P2pStatusResult {
                peer_count,
                tag: Cow::Borrowed(tag),
                peer_id,
                our_topoheight,
                best_topoheight,
                max_peers
            }))
        },
        None => Err(InternalRpcError::AnyError(ApiError::NoP2p.into()))
    }
}

async fn get_mempool<S: Storage>(blockchain: Arc<Blockchain<S>>, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }

    let mempool = blockchain.get_mempool().read().await;
    let storage = blockchain.get_storage().read().await;
    let mut transactions: Vec<Value> = Vec::new();
    for tx in mempool.get_sorted_txs() {
        let transaction = mempool.view_tx(tx.get_hash()).context("Error while retrieving TX from mempool")?;
        transactions.push(get_transaction_response(&*storage, transaction, tx.get_hash()).await?);
    }

    Ok(json!(transactions))
}

async fn get_blocks_at_height<S: Storage>(blockchain: Arc<Blockchain<S>>, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetBlocksAtHeightParams = parse_params(body)?;
    let storage = blockchain.get_storage().read().await;

    let mut blocks = Vec::new();
    for hash in storage.get_blocks_at_height(params.height).await.context("Error while retrieving blocks at height")? {
        blocks.push(get_block_response_for_hash(&blockchain, &storage, hash, params.include_txs).await?)
    }
    Ok(json!(blocks))
}

async fn get_tips<S: Storage>(blockchain: Arc<Blockchain<S>>, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }
    let storage = blockchain.get_storage().read().await;
    let tips = storage.get_tips().await.context("Error while retrieving tips")?;
    Ok(json!(tips))
}

const MAX_DAG_ORDER: u64 = 64;
// get dag order based on params
// if no params found, get order of last 64 blocks
async fn get_dag_order<S: Storage>(blockchain: Arc<Blockchain<S>>, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetRangeParams = parse_params(body)?;

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
        return Err(InternalRpcError::InvalidRequest)
    }

    let count = end_topoheight - start_topoheight;
    if count > MAX_DAG_ORDER { // only retrieve max 64 blocks hash per request
        debug!("get dag order requested count: {}", count);
        return Err(InternalRpcError::InvalidRequest) 
    }

    let storage = blockchain.get_storage().read().await;
    let mut order = Vec::with_capacity(count as usize);
    for i in start_topoheight..=end_topoheight {
        let hash = storage.get_hash_at_topo_height(i).await.context("Error while retrieving hash at topo height")?;
        order.push(hash);
    }

    Ok(json!(order))
}

const MAX_BLOCKS: u64 = 20;
// get blocks between range of topoheight
// if no params found, get last 20 blocks header
async fn get_blocks<S: Storage>(blockchain: Arc<Blockchain<S>>, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetRangeParams = parse_params(body)?;

    let current_topoheight = blockchain.get_topo_height();
    let start_topoheight = params.start_topoheight.unwrap_or_else(|| {
        if params.end_topoheight.is_none() && current_topoheight > MAX_BLOCKS {
            current_topoheight - MAX_BLOCKS
        } else {
            0
        }
    });

    let end_topoheight = params.end_topoheight.unwrap_or(current_topoheight);
    if end_topoheight < start_topoheight || end_topoheight > current_topoheight {
        debug!("get blocks range: start = {}, end = {}, max = {}", start_topoheight, end_topoheight, current_topoheight);
        return Err(InternalRpcError::InvalidRequest)
    }

    let count = end_topoheight - start_topoheight;
    if count > MAX_BLOCKS { // only retrieve max 20 blocks hash per request
        debug!("get blocks requested count: {}", count);
        return Err(InternalRpcError::InvalidRequest) 
    }

    let storage = blockchain.get_storage().read().await;
    let mut blocks = Vec::with_capacity(count as usize);
    for i in start_topoheight..=end_topoheight {
        let hash = storage.get_hash_at_topo_height(i).await.context("Error while retrieving hash at topo height")?;
        let response = get_block_response_for_hash(&blockchain, &storage, hash, false).await?;
        blocks.push(response);
    }

    Ok(json!(blocks))
}

const MAX_TXS: usize = 20;
// get up to 20 transactions at once
// if a tx hash is not present, we keep the order and put json "null" value
async fn get_transactions<S: Storage>(blockchain: Arc<Blockchain<S>>, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetTransactionsParams = parse_params(body)?;

    let hashes = params.tx_hashes;
    if  hashes.len() > MAX_TXS {
        return Err(InternalRpcError::InvalidRequest) 
    }

    let storage = blockchain.get_storage().read().await;
    let mut transactions: Vec<Option<Value>> = Vec::with_capacity(hashes.len());
    for hash in hashes {
        let tx = match get_transaction_response_for_hash(&*storage, &hash).await {
            Ok(data) => Some(data),
            Err(e) => {
                debug!("Error while retrieving tx {} from storage: {}", hash, e);
                None
            }
        };
        transactions.push(tx);
    }

    Ok(json!(transactions))
}