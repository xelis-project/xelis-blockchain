use crate::{core::{blockchain::{Blockchain, get_block_reward}, storage::Storage, error::BlockchainError, mempool::Mempool}, p2p::peer::Peer, config::{DEV_FEES, MAXIMUM_SUPPLY}};
use super::{InternalRpcError, ApiError};
use anyhow::Context as AnyContext;
use human_bytes::human_bytes;
use serde_json::{json, Value};
use xelis_common::{
    api::{daemon::{
        BlockType,
        BlockResponse,
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
        GetTopoHeightRangeParams,
        GetBalanceAtTopoHeightParams,
        GetLastBalanceResult,
        GetInfoResult,
        GetTopBlockParams,
        GetTransactionsParams,
        TransactionResponse,
        GetHeightRangeParams,
        GetNonceResult,
        GetAssetsParams,
        GetAccountsParams,
        HasNonceResult,
        HasNonceParams,
        GetAssetParams,
        GetAccountHistoryParams,
        AccountHistoryEntry,
        AccountHistoryType,
        GetAccountAssetsParams,
        PeerEntry,
        IsTxExecutedInBlockParams,
        SizeOnDiskResult
    }, DataHash},
    async_handler,
    serializer::Serializer,
    transaction::{Transaction, TransactionType},
    crypto::hash::Hash,
    block::{BlockHeader, Block},
    config::{XELIS_ASSET, VERSION},
    immutable::Immutable,
    rpc_server::{RPCHandler, parse_params, Context},
};
use crate::config::BLOCK_TIME_MILLIS;
use std::{sync::Arc, borrow::Cow};
use log::{info, debug, trace};

pub async fn get_block_type_for_block<S: Storage>(blockchain: &Blockchain<S>, storage: &S, hash: &Hash) -> Result<BlockType, InternalRpcError> {
    Ok(if blockchain.is_block_orphaned_for_storage(storage, hash).await {
        BlockType::Orphaned
    } else if blockchain.is_sync_block(storage, hash).await.context("Error while checking if block is sync")? {
        BlockType::Sync
    } else if blockchain.is_side_block(storage, hash).await.context("Error while checking if block is side")? {
        BlockType::Side
    } else {
        BlockType::Normal
    })
}

pub async fn get_block_response_for_hash<S: Storage>(blockchain: &Blockchain<S>, storage: &S, hash: Hash, include_txs: bool) -> Result<Value, InternalRpcError> {
    if !storage.has_block(&hash).await.context("Error while checking if block exist")? {
        return Err(InternalRpcError::AnyError(BlockchainError::BlockNotFound(hash).into()))
    }

    let (topoheight, supply, reward) = if storage.is_block_topological_ordered(&hash).await {
        let topoheight = storage.get_topo_height_for_hash(&hash).await.context("Error while retrieving topo height")?;
        (
            Some(topoheight),
            Some(storage.get_supply_at_topo_height(topoheight).await.context("Error while retrieving supply")?),
            Some(storage.get_block_reward_at_topo_height(topoheight).context("Error while retrieving block reward")?),
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
    let value: Value = if include_txs {
        let block = storage.get_block(&hash).await.context("Error while retrieving full block")?;

        let total_size_in_bytes = block.size();
        let mut total_fees = 0;
        for (tx, tx_hash) in block.get_transactions().iter().zip(block.get_txs_hashes()) {
            // check that the TX was correctly executed in this block
            // retrieve all fees for valid txs
            if storage.is_tx_executed_in_block(tx_hash, &hash).context("Error while checking if tx was executed")? {
                    total_fees += tx.get_fee();
            }
        }

        let data: DataHash<'_, Block> = DataHash { hash: Cow::Borrowed(&hash), data: Cow::Owned(block) };
        json!(BlockResponse { topoheight, block_type, cumulative_difficulty, difficulty, supply, reward, total_fees: Some(total_fees), total_size_in_bytes, data })
    } else {
        let block = storage.get_block_header_by_hash(&hash).await.context("Error while retrieving full block")?;

        let mut total_size_in_bytes = block.size();
        for tx_hash in block.get_txs_hashes() {
            total_size_in_bytes += storage.get_transaction_size(tx_hash).await.context(format!("Error while retrieving transaction {hash} size"))?;
        }

        let data: DataHash<'_, Arc<BlockHeader>> = DataHash { hash: Cow::Borrowed(&hash), data: Cow::Borrowed(&block) };
        json!(BlockResponse { topoheight, block_type, cumulative_difficulty, difficulty, supply, reward, total_fees: None, total_size_in_bytes, data })
    };

    Ok(value)
}

pub async fn get_transaction_response<S: Storage>(storage: &S, tx: &Arc<Transaction>, hash: &Hash, in_mempool: bool, first_seen: Option<u64>) -> Result<Value, InternalRpcError> {
    let blocks = if storage.has_tx_blocks(hash).context("Error while checking if tx in included in blocks")? {
        Some(storage.get_blocks_for_tx(hash).context("Error while retrieving in which blocks its included")?)
    } else {
        None
    };

    let data: DataHash<'_, Arc<Transaction>> = DataHash { hash: Cow::Borrowed(&hash), data: Cow::Borrowed(tx) };
    let executed_in_block = storage.get_block_executer_for_tx(hash).ok();
    Ok(json!(TransactionResponse { blocks, executed_in_block, data, in_mempool, first_seen }))
}

// first check on disk, then check in mempool
pub async fn get_transaction_response_for_hash<S: Storage>(storage: &S, mempool: &Mempool, hash: &Hash) -> Result<Value, InternalRpcError> {
    match storage.get_transaction(hash).await {
        Ok(tx) => get_transaction_response(storage, &tx, hash, false, None).await,
        Err(_) => {
            let tx = mempool.get_sorted_tx(hash).context("Error while retrieving transaction from disk and mempool")?;
            get_transaction_response(storage, &tx.get_tx(), hash, true, Some(tx.get_first_seen())).await
        }
    }
}

pub async fn get_peer_entry(peer: &Peer) -> PeerEntry {
    let top_block_hash = peer.get_top_block_hash().lock().await.clone();
    let peer_peers = peer.get_peers(false).lock().await.clone();
    PeerEntry {
        id: peer.get_id(),
        addr: Cow::Borrowed(peer.get_outgoing_address()),
        tag: Cow::Borrowed(peer.get_node_tag()),
        version: Cow::Borrowed(peer.get_version()),
        top_block_hash,
        topoheight: peer.get_topoheight(),
        height: peer.get_height(),
        last_ping: peer.get_last_ping(),
        peers: peer_peers,
        pruned_topoheight: peer.get_pruned_topoheight(),
        cumulative_difficulty: peer.get_cumulative_difficulty()
    }
}

pub fn register_methods<S: Storage>(handler: &mut RPCHandler<Arc<Blockchain<S>>>) {
    info!("Registering RPC methods...");
    handler.register_method("get_version", async_handler!(version::<S>));
    handler.register_method("get_height", async_handler!(get_height::<S>));
    handler.register_method("get_topoheight", async_handler!(get_topoheight::<S>));
    handler.register_method("get_stableheight", async_handler!(get_stableheight::<S>));
    handler.register_method("get_block_template", async_handler!(get_block_template::<S>));
    handler.register_method("get_block_at_topoheight", async_handler!(get_block_at_topoheight::<S>));
    handler.register_method("get_blocks_at_height", async_handler!(get_blocks_at_height::<S>));
    handler.register_method("get_block_by_hash", async_handler!(get_block_by_hash::<S>));
    handler.register_method("get_top_block", async_handler!(get_top_block::<S>));
    handler.register_method("submit_block", async_handler!(submit_block::<S>));
    handler.register_method("get_last_balance", async_handler!(get_last_balance::<S>));
    handler.register_method("get_balance_at_topoheight", async_handler!(get_balance_at_topoheight::<S>));
    handler.register_method("get_info", async_handler!(get_info::<S>));
    handler.register_method("get_nonce", async_handler!(get_nonce::<S>));
    handler.register_method("has_nonce", async_handler!(has_nonce::<S>));
    handler.register_method("get_asset", async_handler!(get_asset::<S>));
    handler.register_method("get_assets", async_handler!(get_assets::<S>));
    handler.register_method("count_assets", async_handler!(count_assets::<S>));
    handler.register_method("count_accounts", async_handler!(count_accounts::<S>));
    handler.register_method("count_transactions", async_handler!(count_transactions::<S>));
    handler.register_method("submit_transaction", async_handler!(submit_transaction::<S>));
    handler.register_method("get_transaction", async_handler!(get_transaction::<S>));
    handler.register_method("p2p_status", async_handler!(p2p_status::<S>));
    handler.register_method("get_peers", async_handler!(get_peers::<S>));
    handler.register_method("get_mempool", async_handler!(get_mempool::<S>));
    handler.register_method("get_tips", async_handler!(get_tips::<S>));
    handler.register_method("get_dag_order", async_handler!(get_dag_order::<S>));
    handler.register_method("get_blocks_range_by_topoheight", async_handler!(get_blocks_range_by_topoheight::<S>));
    handler.register_method("get_blocks_range_by_height", async_handler!(get_blocks_range_by_height::<S>));
    handler.register_method("get_transactions", async_handler!(get_transactions::<S>));
    handler.register_method("get_account_history", async_handler!(get_account_history::<S>));
    handler.register_method("get_account_assets", async_handler!(get_account_assets::<S>));
    handler.register_method("get_accounts", async_handler!(get_accounts::<S>));
    handler.register_method("is_tx_executed_in_block", async_handler!(is_tx_executed_in_block::<S>));
    handler.register_method("get_dev_fee_thresholds", async_handler!(get_dev_fee_thresholds::<S>));
    handler.register_method("get_size_on_disk", async_handler!(get_size_on_disk::<S>));
}

async fn version<S: Storage>(_: Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }
    Ok(json!(VERSION))
}

async fn get_height<S: Storage>(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    Ok(json!(blockchain.get_height()))
}

async fn get_topoheight<S: Storage>(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    Ok(json!(blockchain.get_topo_height()))
}

async fn get_stableheight<S: Storage>(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    Ok(json!(blockchain.get_stable_height()))
}

async fn get_block_at_topoheight<S: Storage>(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetBlockAtTopoHeightParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let hash = storage.get_hash_at_topo_height(params.topoheight).await.context("Error while retrieving hash at topo height")?;
    get_block_response_for_hash(&blockchain, &storage, hash, params.include_txs).await
}

async fn get_block_by_hash<S: Storage>(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetBlockByHashParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    get_block_response_for_hash(&blockchain, &storage, params.hash.into_owned(), params.include_txs).await
}

async fn get_top_block<S: Storage>(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetTopBlockParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let hash = blockchain.get_top_block_hash_for_storage(&storage).await.context("Error while retrieving top block hash")?;
    get_block_response_for_hash(&blockchain, &storage, hash, params.include_txs).await
}

async fn get_block_template<S: Storage>(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetBlockTemplateParams = parse_params(body)?;
    if !params.address.is_normal() {
        return Err(InternalRpcError::AnyError(ApiError::ExpectedNormalAddress.into()))
    }

    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    if params.address.is_mainnet() != blockchain.get_network().is_mainnet() {
        return Err(InternalRpcError::AnyError(BlockchainError::InvalidNetwork.into()))
    }

    let storage = blockchain.get_storage().read().await;
    let block = blockchain.get_block_template_for_storage(&storage, params.address.into_owned().to_public_key()).await.context("Error while retrieving block template")?;
    let difficulty = blockchain.get_difficulty_at_tips(&*storage, block.get_tips()).await.context("Error while retrieving difficulty at tips")?;
    let height = block.height;
    Ok(json!(GetBlockTemplateResult { template: block.to_hex(), height, difficulty }))
}

async fn submit_block<S: Storage>(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: SubmitBlockParams = parse_params(body)?;
    let header = BlockHeader::from_hex(params.block_template)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    // TODO add block hashing blob on block template
    let block = blockchain.build_block_from_header(Immutable::Owned(header)).await.context("Error while building block from header")?;
    blockchain.add_new_block(block, true, true).await.context("Error while adding new block to chain")?;
    Ok(json!(true))
}

async fn get_last_balance<S: Storage>(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetBalanceParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
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

async fn get_info<S: Storage>(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let height = blockchain.get_height();
    let topoheight = blockchain.get_topo_height();
    let stableheight = blockchain.get_stable_height();
    let (top_block_hash, circulating_supply, pruned_topoheight, average_block_time) = {
        let storage = blockchain.get_storage().read().await;
        let top_block_hash = storage.get_hash_at_topo_height(topoheight).await.context("Error while retrieving hash at topo height")?;
        let supply = storage.get_supply_at_topo_height(topoheight).await.context("Error while retrieving supply at topo height")?;
        let pruned_topoheight = storage.get_pruned_topoheight().context("Error while retrieving pruned topoheight")?;
        let average_block_time = blockchain.get_average_block_time_for_storage(&storage).await.context("Error while retrieving average block time")?;
        (top_block_hash, supply, pruned_topoheight, average_block_time)
    };
    let difficulty = blockchain.get_difficulty();
    let block_time_target = BLOCK_TIME_MILLIS;
    let block_reward = get_block_reward(circulating_supply);
    let mempool_size = blockchain.get_mempool_size().await;
    let version = VERSION.into();
    let network = *blockchain.get_network();

    Ok(json!(GetInfoResult {
        height,
        topoheight,
        stableheight,
        pruned_topoheight,
        top_block_hash,
        circulating_supply,
        maximum_supply: MAXIMUM_SUPPLY,
        difficulty,
        block_time_target,
        average_block_time,
        block_reward,
        mempool_size,
        version,
        network
    }))
}

async fn get_balance_at_topoheight<S: Storage>(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetBalanceAtTopoHeightParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
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

async fn has_nonce<S: Storage>(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: HasNonceParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    if params.address.is_mainnet() != blockchain.get_network().is_mainnet() {
        return Err(InternalRpcError::AnyError(BlockchainError::InvalidNetwork.into()))
    }

    let storage = blockchain.get_storage().read().await;
    let exist = if let Some(topoheight) = params.topoheight {
        storage.has_nonce_at_exact_topoheight(params.address.get_public_key(), topoheight).await.context("Error while checking nonce at topo for account")?
    } else {
        storage.has_nonce(params.address.get_public_key()).await.context("Error while checking nonce for account")?
    };

    Ok(json!(HasNonceResult { exist }))
}

async fn get_nonce<S: Storage>(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetNonceParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    if params.address.is_mainnet() != blockchain.get_network().is_mainnet() {
        return Err(InternalRpcError::AnyError(BlockchainError::InvalidNetwork.into()))
    }

    let storage = blockchain.get_storage().read().await;
    let (topoheight, version) = if let Some(topoheight) = params.topoheight {
        (topoheight, storage.get_nonce_at_exact_topoheight(params.address.get_public_key(), topoheight).await
            .context("Error while retrieving nonce at topo for account")?)
    } else {
         storage.get_last_nonce(params.address.get_public_key()).await
            .context("Error while retrieving nonce for account")?
    };

    Ok(json!(GetNonceResult { topoheight, version }))
}

async fn get_asset<S: Storage>(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetAssetParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let asset = storage.get_asset_data(&params.asset).context("Asset was not found")?;
    Ok(json!(asset))
}

const MAX_ASSETS: usize = 100;

async fn get_assets<S: Storage>(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetAssetsParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let maximum = if let Some(maximum) = params.maximum {
        if maximum > MAX_ASSETS {
            return Err(InternalRpcError::InvalidRequest).context(format!("Maximum assets requested cannot be greater than {}", MAX_ASSETS))?
        }
        maximum
    } else {
        MAX_ASSETS
    };
    let skip = params.skip.unwrap_or(0);
    let storage = blockchain.get_storage().read().await;
    let min = params.minimum_topoheight.unwrap_or(0);
    let max =  params.maximum_topoheight.unwrap_or_else(|| blockchain.get_topo_height());
    let assets = storage.get_partial_assets(maximum, skip, min, max).await
        .context("Error while retrieving registered assets")?;

    Ok(json!(assets))
}

async fn count_assets<S: Storage>(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let count = storage.count_assets().context("Error while retrieving assets count")?;
    Ok(json!(count))
}

async fn count_accounts<S: Storage>(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let count = storage.count_accounts().context("Error while retrieving accounts count")?;
    Ok(json!(count))
}

async fn count_transactions<S: Storage>(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let count = storage.count_transactions().context("Error while retrieving transactions count")?;
    Ok(json!(count))
}

async fn submit_transaction<S: Storage>(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: SubmitTransactionParams = parse_params(body)?;
    let transaction = Transaction::from_hex(params.data)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    blockchain.add_tx_to_mempool(transaction, true).await.map_err(|e| InternalRpcError::AnyError(e.into()))?;
    Ok(json!(true))
}

async fn get_transaction<S: Storage>(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetTransactionParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let mempool = blockchain.get_mempool().read().await;

    get_transaction_response_for_hash(&*storage, &mempool, &params.hash).await
}

async fn p2p_status<S: Storage>(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }

    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let p2p = blockchain.get_p2p().read().await;
    match p2p.as_ref() {
        Some(p2p) => {
            let tag = p2p.get_tag();
            let peer_id = p2p.get_peer_id();
            let best_topoheight = p2p.get_best_topoheight().await;
            let median_topoheight = p2p.get_median_topoheight_of_peers().await;
            let max_peers = p2p.get_max_peers();
            let our_topoheight = blockchain.get_topo_height();
            let peer_count = p2p.get_peer_count().await;

            Ok(json!(P2pStatusResult {
                peer_count,
                tag: Cow::Borrowed(tag),
                peer_id,
                our_topoheight,
                best_topoheight,
                median_topoheight,
                max_peers
            }))
        },
        None => Err(InternalRpcError::AnyError(ApiError::NoP2p.into()))
    }
}

async fn get_peers<S: Storage>(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let p2p = blockchain.get_p2p().read().await;
    match p2p.as_ref() {
        Some(p2p) => {
            let peer_list = p2p.get_peer_list().read().await;
            let mut peers = Vec::new();
            for p in  peer_list.get_peers().values() {
                peers.push(get_peer_entry(p).await);
            }
            Ok(json!(peers))
        },
        None => Err(InternalRpcError::AnyError(ApiError::NoP2p.into()))
    }
}

async fn get_mempool<S: Storage>(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let mempool = blockchain.get_mempool().read().await;
    let mut transactions: Vec<Value> = Vec::new();
    for (hash, sorted_tx) in mempool.get_txs() {
        transactions.push(get_transaction_response(&*storage, sorted_tx.get_tx(), hash, true, Some(sorted_tx.get_first_seen())).await?);
    }

    Ok(json!(transactions))
}

async fn get_blocks_at_height<S: Storage>(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetBlocksAtHeightParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;

    let mut blocks = Vec::new();
    for hash in storage.get_blocks_at_height(params.height).await.context("Error while retrieving blocks at height")? {
        blocks.push(get_block_response_for_hash(&blockchain, &storage, hash, params.include_txs).await?)
    }
    Ok(json!(blocks))
}

async fn get_tips<S: Storage>(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let tips = storage.get_tips().await.context("Error while retrieving tips")?;
    Ok(json!(tips))
}

const MAX_DAG_ORDER: u64 = 64;
// get dag order based on params
// if no params found, get order of last 64 blocks
async fn get_dag_order<S: Storage>(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetTopoHeightRangeParams = parse_params(body)?;

    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let current = blockchain.get_topo_height();
    let (start_topoheight, end_topoheight) = get_range(params.start_topoheight, params.end_topoheight, MAX_DAG_ORDER, current)?;
    let count = end_topoheight - start_topoheight;

    let storage = blockchain.get_storage().read().await;
    let mut order = Vec::with_capacity(count as usize);
    for i in start_topoheight..=end_topoheight {
        let hash = storage.get_hash_at_topo_height(i).await.context("Error while retrieving hash at topo height")?;
        order.push(hash);
    }

    Ok(json!(order))
}

const MAX_BLOCKS: u64 = 20;

fn get_range(start: Option<u64>, end: Option<u64>, maximum: u64, current: u64) -> Result<(u64, u64), InternalRpcError> {
    let range_start = start.unwrap_or_else(|| {
        if end.is_none() && current > maximum {
            current - maximum
        } else {
            0
        }
    });

    let range_end = end.unwrap_or(current);
    if range_end < range_start || range_end > current {
        debug!("get range: start = {}, end = {}, max = {}", range_start, range_end, current);
        return Err(InternalRpcError::InvalidRequest).context(format!("Invalid range requested, start: {}, end: {}", range_start, range_end))?
    }

    let count = range_end - range_start;
    if count > maximum { // only retrieve max 20 blocks hash per request
        debug!("get range requested count: {}", count);
        return Err(InternalRpcError::InvalidRequest).context(format!("Invalid range count requested, received {} but maximum is {}", count, maximum))?
    }

    Ok((range_start, range_end))
}

// get blocks between range of topoheight
// if no params found, get last 20 blocks header
async fn get_blocks_range_by_topoheight<S: Storage>(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetTopoHeightRangeParams = parse_params(body)?;

    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let current_topoheight = blockchain.get_topo_height();
    let (start_topoheight, end_topoheight) = get_range(params.start_topoheight, params.end_topoheight, MAX_BLOCKS, current_topoheight)?;

    let storage = blockchain.get_storage().read().await;
    let mut blocks = Vec::with_capacity((end_topoheight - start_topoheight) as usize);
    for i in start_topoheight..=end_topoheight {
        let hash = storage.get_hash_at_topo_height(i).await.context("Error while retrieving hash at topo height")?;
        let response = get_block_response_for_hash(&blockchain, &storage, hash, false).await?;
        blocks.push(response);
    }

    Ok(json!(blocks))
}

// get blocks between range of height
// if no params found, get last 20 blocks header
// you can only request 
async fn get_blocks_range_by_height<S: Storage>(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetHeightRangeParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let current_height = blockchain.get_height();
    let (start_height, end_height) = get_range(params.start_height, params.end_height, MAX_BLOCKS, current_height)?;

    let storage = blockchain.get_storage().read().await;
    let mut blocks = Vec::with_capacity((end_height - start_height) as usize);
    for i in start_height..=end_height {
        let blocks_at_height = storage.get_blocks_at_height(i).await.context("Error while retrieving blocks at height")?;
        for hash in blocks_at_height {
            let response = get_block_response_for_hash(&blockchain, &storage, hash, false).await?;
            blocks.push(response);
        }
    }

    Ok(json!(blocks))
}

const MAX_TXS: usize = 20;
// get up to 20 transactions at once
// if a tx hash is not present, we keep the order and put json "null" value
async fn get_transactions<S: Storage>(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetTransactionsParams = parse_params(body)?;

    let hashes = params.tx_hashes;
    if  hashes.len() > MAX_TXS {
        return Err(InternalRpcError::InvalidRequest).context(format!("Too many requested txs: {}, maximum is {}", hashes.len(), MAX_TXS))?
    }

    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let mempool = blockchain.get_mempool().read().await;
    let mut transactions: Vec<Option<Value>> = Vec::with_capacity(hashes.len());
    for hash in hashes {
        let tx = match get_transaction_response_for_hash(&*storage, &mempool, &hash).await {
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

const MAX_HISTORY: usize = 20;
// retrieve all history changes for an account on an asset
async fn get_account_history<S: Storage>(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetAccountHistoryParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    if params.address.is_mainnet() != blockchain.get_network().is_mainnet() {
        return Err(InternalRpcError::AnyError(BlockchainError::InvalidNetwork.into()))
    }

    let key = params.address.get_public_key();
    let minimum_topoheight = params.minimum_topoheight.unwrap_or(0);
    let storage = blockchain.get_storage().read().await;
    let pruned_topoheight = storage.get_pruned_topoheight().context("Error while retrieving pruned topoheight")?.unwrap_or(0);
    let mut version = if let Some(topo) = params.maximum_topoheight {
        if topo < pruned_topoheight {
            return Err(InternalRpcError::CustomStr("Maximum topoheight is lower than pruned topoheight"));
        }
        storage.get_balance_at_maximum_topoheight(key, &params.asset, topo).await.context(format!("Error while retrieving balance at topo height {topo}"))?
    } else {
        Some(storage.get_last_balance(key, &params.asset).await.context("Error while retrieving last balance")?)
    };

    let mut history_count = 0;
    let mut history = Vec::new();
    loop {
        if let Some((topo, versioned_balance)) = version.take() {
            trace!("Searching history at topoheight {}", topo);
            if topo < minimum_topoheight || topo < pruned_topoheight {
                break;
            }

            let (hash, block_header) = storage.get_block_header_at_topoheight(topo).await.context(format!("Error while retrieving block header at topo height {topo}"))?;
            if params.asset == XELIS_ASSET && *block_header.get_miner() == *key {
                let reward = storage.get_block_reward_at_topo_height(topo).context(format!("Error while retrieving reward at topo height {topo}"))?;
                let history_type = AccountHistoryType::Mining { reward };
                history.push(AccountHistoryEntry {
                    topoheight: topo,
                    hash: hash.clone(),
                    history_type,
                    block_timestamp: block_header.get_timestamp()
                });
            }

            for tx_hash in block_header.get_transactions() {
                trace!("Searching tx {} in block {}", tx_hash, hash);
                let tx = storage.get_transaction(tx_hash).await.context(format!("Error while retrieving transaction {tx_hash} from block {hash}"))?;
                let is_sender = *tx.get_owner() == *key;
                match tx.get_data() {
                    TransactionType::Transfer(transfers) => {
                        for transfer in transfers {
                            if transfer.asset == params.asset {
                                if transfer.to == *key {
                                    history.push(AccountHistoryEntry {
                                        topoheight: topo,
                                        hash: tx_hash.clone(),
                                        history_type: AccountHistoryType::Incoming { amount: transfer.amount },
                                        block_timestamp: block_header.get_timestamp()
                                    });
                                }

                                if is_sender {
                                    history.push(AccountHistoryEntry {
                                        topoheight: topo,
                                        hash: tx_hash.clone(),
                                        history_type: AccountHistoryType::Outgoing { amount: transfer.amount },
                                        block_timestamp: block_header.get_timestamp()
                                    });
                                }
                            }
                        }
                    }
                    TransactionType::Burn { asset, amount } => {
                        if *asset == params.asset {
                            if is_sender {
                                history.push(AccountHistoryEntry {
                                    topoheight: topo,
                                    hash: tx_hash.clone(),
                                    history_type: AccountHistoryType::Burn { amount: *amount },
                                    block_timestamp: block_header.get_timestamp()
                                });
                            }
                        }
                    },
                    _ => {}
                }
            }

            history_count += 1;
            if history_count >= MAX_HISTORY {
                break;   
            }        
    
            if let Some(previous) = versioned_balance.get_previous_topoheight() {
                if previous < pruned_topoheight {
                    break;
                }
                version = Some((previous, storage.get_balance_at_exact_topoheight(key, &params.asset, previous).await.context(format!("Error while retrieving previous balance at topo height {previous}"))?));
            }
        } else {
            break;
        }
    }

    Ok(json!(history))
}

async fn get_account_assets<S: Storage>(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetAccountAssetsParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    if params.address.is_mainnet() != blockchain.get_network().is_mainnet() {
        return Err(InternalRpcError::AnyError(BlockchainError::InvalidNetwork.into()))
    }

    let key = params.address.get_public_key();
    let storage = blockchain.get_storage().read().await;
    let assets = storage.get_assets_for(key).await.context("Error while retrieving assets for account")?;
    Ok(json!(assets))
}

const MAX_ACCOUNTS: usize = 100;
// retrieve all available accounts (each account got at least one interaction on chain)
async fn get_accounts<S: Storage>(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetAccountsParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let topoheight = blockchain.get_topo_height();
    let maximum = if let Some(maximum) = params.maximum {
        if maximum > MAX_ACCOUNTS {
            return Err(InternalRpcError::InvalidRequest).context(format!("Maximum accounts requested cannot be greater than {}", MAX_ACCOUNTS))?
        }
        maximum
    } else {
        MAX_ACCOUNTS
    };
    let skip = params.skip.unwrap_or(0);
    let minimum_topoheight = if let Some(minimum) = params.minimum_topoheight {
        if minimum > topoheight {
            return Err(InternalRpcError::InvalidRequest).context(format!("Minimum topoheight requested cannot be greater than {}", topoheight))?
        }

        minimum
    } else {
        0
    };
    let maximum_topoheight = if let Some(maximum) = params.maximum_topoheight {
        if maximum > topoheight {
            return Err(InternalRpcError::InvalidRequest).context(format!("Maximum topoheight requested cannot be greater than {}", topoheight))?
        }

        if maximum < minimum_topoheight {
            return Err(InternalRpcError::InvalidRequest).context(format!("Maximum topoheight requested must be greater or equal to {}", minimum_topoheight))?
        }
        maximum
    } else {
        topoheight
    };

    let storage = blockchain.get_storage().read().await;
    let accounts = storage.get_partial_keys(maximum, skip, minimum_topoheight, maximum_topoheight).await.context("Error while retrieving accounts")?;

    Ok(json!(accounts))
}

// Check if the asked TX is executed in the block
async fn is_tx_executed_in_block<S: Storage>(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: IsTxExecutedInBlockParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    Ok(json!(storage.is_tx_executed_in_block(&params.tx_hash, &params.block_hash).context("Error while checking if tx was executed in block")?))
}

// Get the configured dev fees
async fn get_dev_fee_thresholds<S: Storage>(_: Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }

    Ok(json!(DEV_FEES))
}

// Get the configured dev fees
async fn get_size_on_disk<S: Storage>(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let size_bytes = storage.get_size_on_disk().await.context("Error while retrieving size on disk")?;
    let size_formatted = human_bytes(size_bytes as f64);

    Ok(json!(SizeOnDiskResult {
        size_bytes,
        size_formatted
    }))
}