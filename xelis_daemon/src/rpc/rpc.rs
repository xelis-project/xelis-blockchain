use crate::{
    config::{
        get_hard_forks as get_configured_hard_forks,
        BLOCK_TIME_MILLIS,
        DEV_FEES,
        DEV_PUBLIC_KEY
    },
    core::{
        blockchain::{
            get_block_dev_fee,
            get_block_reward,
            Blockchain
        },
        hard_fork::get_pow_algorithm_for_version,
        error::BlockchainError,
        mempool::Mempool,
        storage::*,
    },
    p2p::peer::Peer,
    BLOCK_TIME
};
use super::{InternalRpcError, ApiError};
use xelis_common::{
    api::{
        daemon::*,
        RPCContractOutput,
        RPCTransaction,
        SplitAddressParams,
        SplitAddressResult,
    },
    asset::RPCAssetData,
    async_handler,
    block::{
        Block,
        BlockHeader,
        MinerWork,
        TopoHeight
    },
    config::{
        MAXIMUM_SUPPLY,
        MAX_TRANSACTION_SIZE,
        VERSION,
        XELIS_ASSET
    },
    context::Context,
    crypto::{Address, AddressType, Hash},
    difficulty::{
        CumulativeDifficulty,
        Difficulty
    },
    immutable::Immutable,
    rpc_server::{
        parse_params,
        RPCHandler
    },
    serializer::Serializer,
    time::TimestampSeconds,
    transaction::{
        Transaction,
        TransactionType
    },
    utils::format_hashrate
};
use anyhow::Context as AnyContext;
use human_bytes::human_bytes;
use serde_json::{json, Value};
use std::{sync::Arc, borrow::Cow};
use log::{info, debug, trace};

// Get the block type using the block hash and the blockchain current state
pub async fn get_block_type_for_block<S: Storage, P: DifficultyProvider + DagOrderProvider + BlocksAtHeightProvider + PrunedTopoheightProvider>(blockchain: &Blockchain<S>, provider: &P, hash: &Hash) -> Result<BlockType, InternalRpcError> {
    Ok(if blockchain.is_block_orphaned_for_storage(provider, hash).await {
        BlockType::Orphaned
    } else if blockchain.is_sync_block(provider, hash).await.context("Error while checking if block is sync")? {
        BlockType::Sync
    } else if blockchain.is_side_block(provider, hash).await.context("Error while checking if block is side")? {
        BlockType::Side
    } else {
        BlockType::Normal
    })
}

async fn get_block_data<S: Storage, P>(blockchain: &Blockchain<S>, provider: &P, hash: &Hash) -> Result<(Option<TopoHeight>, Option<u64>, Option<u64>, BlockType, CumulativeDifficulty, Difficulty), InternalRpcError>
where
    P: DifficultyProvider
    + DagOrderProvider
    + BlocksAtHeightProvider
    + PrunedTopoheightProvider
    + BlockDagProvider
{
    let (topoheight, supply, reward) = if provider.is_block_topological_ordered(hash).await {
        let topoheight = provider.get_topo_height_for_hash(&hash).await.context("Error while retrieving topo height")?;
        (
            Some(topoheight),
            Some(provider.get_supply_at_topo_height(topoheight).await.context("Error while retrieving supply")?),
            Some(provider.get_block_reward_at_topo_height(topoheight).context("Error while retrieving block reward")?),
        )
    } else {
        (
            None,
            None,
            None,
        )
    };

    let block_type = get_block_type_for_block(&blockchain, &*provider, hash).await?;
    let cumulative_difficulty = provider.get_cumulative_difficulty_for_block_hash(hash).await.context("Error while retrieving cumulative difficulty")?;
    let difficulty = provider.get_difficulty_for_block_hash(&hash).await.context("Error while retrieving difficulty")?;

    Ok((topoheight, supply, reward, block_type, cumulative_difficulty, difficulty))
}

pub async fn get_block_response<S: Storage, P>(blockchain: &Blockchain<S>, provider: &P, hash: &Hash, block: &Block, total_size_in_bytes: usize) -> Result<Value, InternalRpcError>
where
    P: DifficultyProvider
    + DagOrderProvider
    + BlocksAtHeightProvider
    + PrunedTopoheightProvider
    + BlockDagProvider
    + ClientProtocolProvider
{
    let (topoheight, supply, reward, block_type, cumulative_difficulty, difficulty) = get_block_data(blockchain, provider, hash).await?;
    let mut total_fees = 0;
    if block_type != BlockType::Orphaned {
        for (tx, tx_hash) in block.get_transactions().iter().zip(block.get_txs_hashes()) {
            // check that the TX was correctly executed in this block
            // retrieve all fees for valid txs
            if provider.is_tx_executed_in_block(tx_hash, &hash).context("Error while checking if tx was executed")? {
                total_fees += tx.get_fee();
            }
        }
    }

    let mainnet = blockchain.get_network().is_mainnet();
    let header = block.get_header();
    let transactions = block.get_transactions()
        .iter()
        .zip(block.get_txs_hashes())
        .map(|(tx, hash)| RPCTransaction::from_tx(tx, hash, mainnet))
        .collect::<Vec<RPCTransaction<'_>>>();

    let (dev_reward, miner_reward) = get_optional_block_rewards(header.get_height(), reward).map(|(dev_reward, miner_reward)| {
        (Some(dev_reward), Some(miner_reward))
    }).unwrap_or((None, None));

    Ok(json!(RPCBlockResponse {
        hash: Cow::Borrowed(hash),
        topoheight,
        block_type,
        cumulative_difficulty: Cow::Borrowed(&cumulative_difficulty),
        difficulty: Cow::Borrowed(&difficulty),
        supply,
        reward,
        dev_reward,
        miner_reward,
        total_fees: Some(total_fees),
        total_size_in_bytes,
        extra_nonce: Cow::Borrowed(header.get_extra_nonce()),
        timestamp: header.get_timestamp(),
        nonce: header.get_nonce(),
        height: header.get_height(),
        version: header.get_version(),
        miner: Cow::Owned(header.get_miner().as_address(mainnet)),
        tips: Cow::Borrowed(header.get_tips()),
        txs_hashes: Cow::Borrowed(header.get_txs_hashes()),
        transactions
    }))
}

// Get block rewards based on height and reward
fn get_block_rewards(height: u64, reward: u64) -> (u64, u64) {
    let dev_fee_percentage = get_block_dev_fee(height);
    let dev_reward = reward * dev_fee_percentage / 100;
    let miner_reward = reward - dev_reward;

    (dev_reward, miner_reward)
}

// Get optional block rewards based on height and reward
fn get_optional_block_rewards(height: u64, reward: Option<u64>) -> Option<(u64, u64)> {
    if let Some(reward) = reward {
        Some(get_block_rewards(height, reward))
    } else {
        None
    }
}

// Get a block response based on data in chain and from parameters
pub async fn get_block_response_for_hash<S: Storage>(blockchain: &Blockchain<S>, storage: &S, hash: &Hash, include_txs: bool) -> Result<Value, InternalRpcError> {
    if !storage.has_block_with_hash(&hash).await.context("Error while checking if block exist")? {
        return Err(InternalRpcError::InvalidParamsAny(BlockchainError::BlockNotFound(hash.clone()).into()))
    }

    let value: Value = if include_txs {
        let block = storage.get_block_by_hash(&hash).await.context("Error while retrieving full block")?;
        let total_size_in_bytes = block.size();
        get_block_response(blockchain, storage, hash, &block, total_size_in_bytes).await?
    } else {
        let (topoheight, supply, reward, block_type, cumulative_difficulty, difficulty) = get_block_data(blockchain, storage, hash).await?;
        let header = storage.get_block_header_by_hash(&hash).await.context("Error while retrieving full block")?;

        // calculate total size in bytes
        let mut total_size_in_bytes = header.size();
        for tx_hash in header.get_txs_hashes() {
            total_size_in_bytes += storage.get_transaction_size(tx_hash).await.context(format!("Error while retrieving transaction {tx_hash} size"))?;
        }

        let mainnet = blockchain.get_network().is_mainnet();
        let (dev_reward, miner_reward) = get_optional_block_rewards(header.get_height(), reward).map(|(dev_reward, miner_reward)| {
            (Some(dev_reward), Some(miner_reward))
        }).unwrap_or((None, None));

        json!(RPCBlockResponse {
            hash: Cow::Borrowed(hash),
            topoheight,
            block_type,
            cumulative_difficulty: Cow::Owned(cumulative_difficulty),
            difficulty: Cow::Owned(difficulty),
            supply,
            reward,
            dev_reward,
            miner_reward,
            total_fees: None,
            total_size_in_bytes,
            extra_nonce: Cow::Borrowed(header.get_extra_nonce()),
            timestamp: header.get_timestamp(),
            nonce: header.get_nonce(),
            height: header.get_height(),
            version: header.get_version(),
            miner: Cow::Owned(header.get_miner().as_address(mainnet)),
            tips: Cow::Borrowed(header.get_tips()),
            txs_hashes: Cow::Borrowed(header.get_txs_hashes()),
            transactions: Vec::with_capacity(0),
        })
    };

    Ok(value)
}

// Transaction response based on data in chain/mempool and from parameters
pub async fn get_transaction_response<S: Storage>(storage: &S, tx: &Arc<Transaction>, hash: &Hash, in_mempool: bool, first_seen: Option<TimestampSeconds>) -> Result<Value, InternalRpcError> {
    let blocks = if storage.has_tx_blocks(hash).context("Error while checking if tx in included in blocks")? {
        Some(storage.get_blocks_for_tx(hash).context("Error while retrieving in which blocks its included")?)
    } else {
        None
    };

    let data = RPCTransaction::from_tx(tx, hash, storage.is_mainnet());
    let executed_in_block = storage.get_block_executor_for_tx(hash).ok();
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

// Get a Peer Entry based on peer data
pub async fn get_peer_entry(peer: &Peer) -> PeerEntry {
    let top_block_hash = { peer.get_top_block_hash().lock().await.clone() };
    let peers = { peer.get_peers().lock().await.clone() };
    let cumulative_difficulty = { peer.get_cumulative_difficulty().lock().await.clone() };
    PeerEntry {
        id: peer.get_id(),
        addr: Cow::Borrowed(peer.get_connection().get_address()),
        local_port: peer.get_local_port(),
        tag: Cow::Borrowed(peer.get_node_tag()),
        version: Cow::Borrowed(peer.get_version()),
        top_block_hash: Cow::Owned(top_block_hash),
        topoheight: peer.get_topoheight(),
        height: peer.get_height(),
        last_ping: peer.get_last_ping(),
        peers: Cow::Owned(peers),
        pruned_topoheight: peer.get_pruned_topoheight(),
        cumulative_difficulty: Cow::Owned(cumulative_difficulty),
        connected_on: peer.get_connection().connected_on(),
        bytes_recv: peer.get_connection().bytes_in(),
        bytes_sent: peer.get_connection().bytes_out(),
    }
}

// This function is used to register all the RPC methods
pub fn register_methods<S: Storage>(handler: &mut RPCHandler<Arc<Blockchain<S>>>, allow_mining_methods: bool) {
    info!("Registering RPC methods...");
    handler.register_method("get_version", async_handler!(version::<S>));
    handler.register_method("get_height", async_handler!(get_height::<S>));
    handler.register_method("get_topoheight", async_handler!(get_topoheight::<S>));
    handler.register_method("get_pruned_topoheight", async_handler!(get_pruned_topoheight::<S>));
    handler.register_method("get_info", async_handler!(get_info::<S>));
    handler.register_method("get_difficulty", async_handler!(get_difficulty::<S>));
    handler.register_method("get_tips", async_handler!(get_tips::<S>));
    handler.register_method("get_dev_fee_thresholds", async_handler!(get_dev_fee_thresholds::<S>));
    handler.register_method("get_size_on_disk", async_handler!(get_size_on_disk::<S>));

    // Retro compatibility, use stable_height
    handler.register_method("get_stableheight", async_handler!(get_stable_height::<S>));
    handler.register_method("get_stable_height", async_handler!(get_stable_height::<S>));
    handler.register_method("get_stable_topoheight", async_handler!(get_stable_topoheight::<S>));
    handler.register_method("get_hard_forks", async_handler!(get_hard_forks::<S>));

    handler.register_method("get_block_at_topoheight", async_handler!(get_block_at_topoheight::<S>));
    handler.register_method("get_blocks_at_height", async_handler!(get_blocks_at_height::<S>));
    handler.register_method("get_block_by_hash", async_handler!(get_block_by_hash::<S>));
    handler.register_method("get_top_block", async_handler!(get_top_block::<S>));

    handler.register_method("get_balance", async_handler!(get_balance::<S>));
    handler.register_method("get_stable_balance", async_handler!(get_stable_balance::<S>));
    handler.register_method("has_balance", async_handler!(has_balance::<S>));
    handler.register_method("get_balance_at_topoheight", async_handler!(get_balance_at_topoheight::<S>));

    handler.register_method("get_nonce", async_handler!(get_nonce::<S>));
    handler.register_method("has_nonce", async_handler!(has_nonce::<S>));
    handler.register_method("get_nonce_at_topoheight", async_handler!(get_nonce_at_topoheight::<S>));

    handler.register_method("get_asset", async_handler!(get_asset::<S>));
    handler.register_method("get_assets", async_handler!(get_assets::<S>));

    handler.register_method("count_assets", async_handler!(count_assets::<S>));
    handler.register_method("count_accounts", async_handler!(count_accounts::<S>));
    handler.register_method("count_transactions", async_handler!(count_transactions::<S>));
    handler.register_method("count_contracts", async_handler!(count_contracts::<S>));

    handler.register_method("submit_transaction", async_handler!(submit_transaction::<S>));
    handler.register_method("get_transaction_executor", async_handler!(get_transaction_executor::<S>));
    handler.register_method("get_transaction", async_handler!(get_transaction::<S>));
    handler.register_method("get_transactions", async_handler!(get_transactions::<S>));
    handler.register_method("is_tx_executed_in_block", async_handler!(is_tx_executed_in_block::<S>));

    handler.register_method("p2p_status", async_handler!(p2p_status::<S>));
    handler.register_method("get_peers", async_handler!(get_peers::<S>));

    handler.register_method("get_mempool", async_handler!(get_mempool::<S>));
    handler.register_method("get_mempool_cache", async_handler!(get_mempool_cache::<S>));
    handler.register_method("get_estimated_fee_rates", async_handler!(get_estimated_fee_rates::<S>));

    handler.register_method("get_dag_order", async_handler!(get_dag_order::<S>));
    handler.register_method("get_blocks_range_by_topoheight", async_handler!(get_blocks_range_by_topoheight::<S>));
    handler.register_method("get_blocks_range_by_height", async_handler!(get_blocks_range_by_height::<S>));

    handler.register_method("get_account_history", async_handler!(get_account_history::<S>));
    handler.register_method("get_account_assets", async_handler!(get_account_assets::<S>));
    handler.register_method("get_accounts", async_handler!(get_accounts::<S>));
    handler.register_method("is_account_registered", async_handler!(is_account_registered::<S>));
    handler.register_method("get_account_registration_topoheight", async_handler!(get_account_registration_topoheight::<S>));

    // Useful methods
    handler.register_method("validate_address", async_handler!(validate_address::<S>));
    handler.register_method("split_address", async_handler!(split_address::<S>));
    handler.register_method("extract_key_from_address", async_handler!(extract_key_from_address::<S>));
    handler.register_method("make_integrated_address", async_handler!(make_integrated_address::<S>));
    handler.register_method("decrypt_extra_data", async_handler!(decrypt_extra_data::<S>));

    // Multisig
    handler.register_method("get_multisig_at_topoheight", async_handler!(get_multisig_at_topoheight::<S>));
    handler.register_method("get_multisig", async_handler!(get_multisig::<S>));
    handler.register_method("has_multisig", async_handler!(has_multisig::<S>));
    handler.register_method("has_multisig_at_topoheight", async_handler!(has_multisig_at_topoheight::<S>));

    // Contracts
    handler.register_method("get_contract_outputs", async_handler!(get_contract_outputs::<S>));
    handler.register_method("get_contract_module", async_handler!(get_contract_module::<S>));
    handler.register_method("get_contract_data", async_handler!(get_contract_data::<S>));
    handler.register_method("get_contract_data_at_topoheight", async_handler!(get_contract_data_at_topoheight::<S>));
    handler.register_method("get_contract_balance", async_handler!(get_contract_balance::<S>));
    handler.register_method("get_contract_balance_at_topoheight", async_handler!(get_contract_balance_at_topoheight::<S>));

    if allow_mining_methods {
        handler.register_method("get_block_template", async_handler!(get_block_template::<S>));
        handler.register_method("get_miner_work", async_handler!(get_miner_work::<S>));
        handler.register_method("submit_block", async_handler!(submit_block::<S>));
    }
}

async fn version<S: Storage>(_: &Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }
    Ok(json!(VERSION))
}

async fn get_height<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    Ok(json!(blockchain.get_height()))
}

async fn get_topoheight<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    Ok(json!(blockchain.get_topo_height()))
}

async fn get_pruned_topoheight<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }

    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let pruned_topoheight = storage.get_pruned_topoheight().await.context("Error while retrieving pruned topoheight")?;

    Ok(json!(pruned_topoheight))
}

async fn get_stable_height<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    Ok(json!(blockchain.get_stable_height()))
}

async fn get_stable_topoheight<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    Ok(json!(blockchain.get_stable_topoheight()))
}

async fn get_hard_forks<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let hard_forks = get_configured_hard_forks(blockchain.get_network());

    Ok(json!(hard_forks))
}


async fn get_block_at_topoheight<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetBlockAtTopoHeightParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let hash = storage.get_hash_at_topo_height(params.topoheight).await.context("Error while retrieving hash at topo height")?;
    get_block_response_for_hash(&blockchain, &storage, &hash, params.include_txs).await
}

async fn get_block_by_hash<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetBlockByHashParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    get_block_response_for_hash(&blockchain, &storage, &params.hash, params.include_txs).await
}

async fn get_top_block<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetTopBlockParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let hash = blockchain.get_top_block_hash_for_storage(&storage).await.context("Error while retrieving top block hash")?;
    get_block_response_for_hash(&blockchain, &storage, &hash, params.include_txs).await
}

async fn get_block_template<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetBlockTemplateParams = parse_params(body)?;
    if !params.address.is_normal() {
        return Err(InternalRpcError::InvalidParamsAny(ApiError::ExpectedNormalAddress.into()))
    }

    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    if params.address.is_mainnet() != blockchain.get_network().is_mainnet() {
        return Err(InternalRpcError::InvalidParamsAny(BlockchainError::InvalidNetwork.into()))
    }

    let storage = blockchain.get_storage().read().await;
    let block = blockchain.get_block_template_for_storage(&storage, params.address.into_owned().to_public_key()).await.context("Error while retrieving block template")?;
    let (difficulty, _) = blockchain.get_difficulty_at_tips(&*storage, block.get_tips().iter()).await.context("Error while retrieving difficulty at tips")?;
    let height = block.height;
    let algorithm = get_pow_algorithm_for_version(block.version);
    let topoheight = blockchain.get_topo_height();
    Ok(json!(GetBlockTemplateResult { template: block.to_hex(), algorithm, height, topoheight, difficulty }))
}

async fn get_miner_work<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetMinerWorkParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;

    let header = BlockHeader::from_hex(&params.template)?;
    let (difficulty, _) = {
        let storage = blockchain.get_storage().read().await;
        blockchain.get_difficulty_at_tips(&*storage, header.get_tips().iter()).await.context("Error while retrieving difficulty at tips")?
    };
    let version = header.get_version();
    let height = header.get_height();

    let mut work = MinerWork::from_block(header);
    if let Some(address) = params.address {
        if !address.is_normal() {
            return Err(InternalRpcError::InvalidParamsAny(ApiError::ExpectedNormalAddress.into()))
        }

        let blockchain: &Arc<Blockchain<S>> = context.get()?;
        if address.is_mainnet() != blockchain.get_network().is_mainnet() {
            return Err(InternalRpcError::InvalidParamsAny(BlockchainError::InvalidNetwork.into()))
        }

        work.set_miner(Cow::Owned(address.into_owned().to_public_key()));
    }

    let algorithm = get_pow_algorithm_for_version(version);
    let topoheight = blockchain.get_topo_height();

    Ok(json!(GetMinerWorkResult { miner_work: work.to_hex(), algorithm, difficulty, height, topoheight }))
}

async fn submit_block<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: SubmitBlockParams = parse_params(body)?;
    let mut header = BlockHeader::from_hex(&params.block_template)?;
    if let Some(work) = params.miner_work {
        let work = MinerWork::from_hex(&work)?;
        header.apply_miner_work(work);
    }

    let blockchain: &Arc<Blockchain<S>> = context.get()?;

    let block = blockchain.build_block_from_header(Immutable::Owned(header)).await?;
    blockchain.add_new_block(block, true, true).await?;
    Ok(json!(true))
}

async fn get_balance<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetBalanceParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    if params.address.is_mainnet() != blockchain.get_network().is_mainnet() {
        return Err(InternalRpcError::InvalidParamsAny(BlockchainError::InvalidNetwork.into()))
    }

    let storage = blockchain.get_storage().read().await;
    let (topoheight, version) = storage.get_last_balance(params.address.get_public_key(), &params.asset).await.context("Error while retrieving last balance")?;
    Ok(json!(GetBalanceResult {
        version,
        topoheight
    }))
}

async fn get_stable_balance<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetBalanceParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    if params.address.is_mainnet() != blockchain.get_network().is_mainnet() {
        return Err(InternalRpcError::InvalidParamsAny(BlockchainError::InvalidNetwork.into()))
    }

    let top_topoheight = blockchain.get_topo_height();
    let stable_topoheight = blockchain.get_stable_topoheight();
    let storage = blockchain.get_storage().read().await;

    let mut stable_version = None;
    if let Some((output_topoheight, version)) = storage.get_output_balance_at_maximum_topoheight(params.address.get_public_key(), &params.asset, top_topoheight).await? {
        if output_topoheight >= stable_topoheight {
            stable_version = Some((output_topoheight, version));
        }
    }

    let (stable_topoheight, version) = if let Some((topoheight, version)) = stable_version {
        (topoheight, version)
    } else {
        storage.get_balance_at_maximum_topoheight(params.address.get_public_key(), &params.asset, stable_topoheight).await?
            .ok_or(InternalRpcError::InvalidRequestStr("no stable balance found for this account"))?
    };

    Ok(json!(GetStableBalanceResult {
        version,
        stable_topoheight,
        stable_block_hash: storage.get_hash_at_topo_height(stable_topoheight).await.context("Error while retrieving hash at topo height")?
    }))
}

async fn has_balance<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: HasBalanceParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    if params.address.is_mainnet() != blockchain.get_network().is_mainnet() {
        return Err(InternalRpcError::InvalidParamsAny(BlockchainError::InvalidNetwork.into()))
    }

    let key = params.address.get_public_key();
    let storage = blockchain.get_storage().read().await;
    let exist = if let Some(topoheight) = params.topoheight {
        storage.has_balance_at_exact_topoheight(key, &params.asset, topoheight).await.context("Error while checking balance at topo for account")?
    } else {
        storage.has_balance_for(key, &params.asset).await.context("Error while checking balance for account")?
    };

    Ok(json!(HasBalanceResult { exist }))
}

async fn get_info<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let height = blockchain.get_height();
    let topoheight = blockchain.get_topo_height();
    let stableheight = blockchain.get_stable_height();
    let (top_block_hash, emitted_supply, burned_supply, pruned_topoheight, average_block_time) = {
        let storage = blockchain.get_storage().read().await;
        let top_block_hash = storage.get_hash_at_topo_height(topoheight).await.context("Error while retrieving hash at topo height")?;
        let emitted_supply = storage.get_supply_at_topo_height(topoheight).await.context("Error while retrieving supply at topo height")?;
        let burned_supply = storage.get_burned_supply_at_topo_height(topoheight).await.context("Error while retrieving burned supply at topoheight")?;
        let pruned_topoheight = storage.get_pruned_topoheight().await.context("Error while retrieving pruned topoheight")?;
        let average_block_time = blockchain.get_average_block_time::<S>(&storage).await.context("Error while retrieving average block time")?;
        (top_block_hash, emitted_supply, burned_supply, pruned_topoheight, average_block_time)
    };
    let difficulty = blockchain.get_difficulty().await;
    let block_time_target = BLOCK_TIME_MILLIS;
    let block_reward = get_block_reward(emitted_supply);
    let (dev_reward, miner_reward) = get_block_rewards(height, block_reward);
    let mempool_size = blockchain.get_mempool_size().await;
    let version = VERSION.into();
    let network = *blockchain.get_network();

    Ok(json!(GetInfoResult {
        height,
        topoheight,
        stableheight,
        pruned_topoheight,
        top_block_hash,
        circulating_supply: emitted_supply - burned_supply,
        burned_supply,
        emitted_supply,
        maximum_supply: MAXIMUM_SUPPLY,
        difficulty,
        block_time_target,
        average_block_time,
        block_reward,
        dev_reward,
        miner_reward,
        mempool_size,
        version,
        network
    }))
}

async fn get_balance_at_topoheight<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetBalanceAtTopoHeightParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let topoheight = blockchain.get_topo_height();
    if params.topoheight > topoheight {
        return Err(InternalRpcError::UnexpectedParams).context("Topoheight cannot be greater than current chain topoheight")?
    }

    if params.address.is_mainnet() != blockchain.get_network().is_mainnet() {
        return Err(InternalRpcError::InvalidParamsAny(BlockchainError::InvalidNetwork.into()))
    }

    let storage = blockchain.get_storage().read().await;
    let balance = storage.get_balance_at_exact_topoheight(params.address.get_public_key(), &params.asset, params.topoheight).await.context("Error while retrieving balance at exact topo height")?;
    Ok(json!(balance))
}

async fn has_nonce<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: HasNonceParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    if params.address.is_mainnet() != blockchain.get_network().is_mainnet() {
        return Err(InternalRpcError::InvalidParamsAny(BlockchainError::InvalidNetwork.into()))
    }

    let storage = blockchain.get_storage().read().await;
    let exist = if let Some(topoheight) = params.topoheight {
        storage.has_nonce_at_exact_topoheight(params.address.get_public_key(), topoheight).await.context("Error while checking nonce at topo for account")?
    } else {
        storage.has_nonce(params.address.get_public_key()).await.context("Error while checking nonce for account")?
    };

    Ok(json!(HasNonceResult { exist }))
}

async fn get_nonce<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetNonceParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    if params.address.is_mainnet() != blockchain.get_network().is_mainnet() {
        return Err(InternalRpcError::InvalidParamsAny(BlockchainError::InvalidNetwork.into()))
    }

    let storage = blockchain.get_storage().read().await;
    let (topoheight, version) = storage.get_last_nonce(params.address.get_public_key()).await
        .context("Error while retrieving nonce for account")?;

    Ok(json!(GetNonceResult { topoheight, version }))
}

async fn get_nonce_at_topoheight<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetNonceAtTopoHeightParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let topoheight = blockchain.get_topo_height();
    if params.topoheight > topoheight {
        return Err(InternalRpcError::UnexpectedParams).context("Topoheight cannot be greater than current chain topoheight")?
    }

    if params.address.is_mainnet() != blockchain.get_network().is_mainnet() {
        return Err(InternalRpcError::InvalidParamsAny(BlockchainError::InvalidNetwork.into()))
    }

    let storage = blockchain.get_storage().read().await;
    let nonce = storage.get_nonce_at_exact_topoheight(params.address.get_public_key(), params.topoheight).await.context("Error while retrieving nonce at exact topo height")?;
    Ok(json!(nonce))
}

async fn get_asset<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetAssetParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let (topoheight, inner) = storage.get_asset(&params.asset).await.context("Asset was not found")?;
    Ok(json!(RPCAssetData {
        asset: Cow::Borrowed(&params.asset),
        topoheight,
        inner
    }))
}

const MAX_ASSETS: usize = 100;

async fn get_assets<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetAssetsParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let maximum = if let Some(maximum) = params.maximum {
        if maximum > MAX_ASSETS {
            return Err(InternalRpcError::InvalidJSONRequest).context(format!("Maximum assets requested cannot be greater than {}", MAX_ASSETS))?
        }
        maximum
    } else {
        MAX_ASSETS
    };
    let skip = params.skip.unwrap_or(0);
    let storage = blockchain.get_storage().read().await;
    let min = params.minimum_topoheight.unwrap_or(0);
    let max =  params.maximum_topoheight.unwrap_or_else(|| blockchain.get_topo_height());
    let assets = storage.get_partial_assets_with_topoheight(maximum, skip, min, max).await
        .context("Error while retrieving registered assets")?;

    let mut response = Vec::with_capacity(assets.len());
    for (asset, (topoheight, inner)) in assets {
        response.push(RPCAssetData {
            asset: Cow::Owned(asset),
            topoheight,
            inner
        });
    }

    Ok(json!(response))
}

async fn count_assets<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let count = storage.count_assets().await.context("Error while retrieving assets count")?;
    Ok(json!(count))
}

async fn count_accounts<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let count = storage.count_accounts().await.context("Error while retrieving accounts count")?;
    Ok(json!(count))
}

async fn count_transactions<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let count = storage.count_transactions().await.context("Error while retrieving transactions count")?;
    Ok(json!(count))
}

async fn count_contracts<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let count = storage.count_contracts().await.context("Error while retrieving contracts count")?;
    Ok(json!(count))
}

async fn submit_transaction<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: SubmitTransactionParams = parse_params(body)?;
    // x2 because of hex encoding
    if params.data.len() > MAX_TRANSACTION_SIZE * 2 {
        return Err(InternalRpcError::InvalidJSONRequest).context(format!("Transaction size cannot be greater than {}", human_bytes(MAX_TRANSACTION_SIZE as f64)))?
    }

    let transaction = Transaction::from_hex(&params.data)
        .map_err(|err| InternalRpcError::InvalidParamsAny(err.into()))?;

    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    blockchain.add_tx_to_mempool(transaction, true).await?;

    Ok(json!(true))
}

async fn get_transaction<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetTransactionParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let mempool = blockchain.get_mempool().read().await;

    get_transaction_response_for_hash(&*storage, &mempool, &params.hash).await
}

async fn get_transaction_executor<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetTransactionExecutorParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;

    let block_executor = storage.get_block_executor_for_tx(&params.hash)?;
    let block_topoheight = storage.get_topo_height_for_hash(&block_executor).await?;
    let block_timestamp = storage.get_timestamp_for_block_hash(&block_executor).await?;

    Ok(json!(
        GetTransactionExecutorResult {
            block_topoheight,
            block_timestamp,
            block_hash: Cow::Borrowed(&block_executor)
        }
    ))
}

async fn p2p_status<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }

    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let p2p = { blockchain.get_p2p().read().await.clone() };
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
        None => Err(InternalRpcError::InvalidParamsAny(ApiError::NoP2p.into()))
    }
}

async fn get_peers<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let p2p = { blockchain.get_p2p().read().await.clone() };
    match p2p.as_ref() {
        Some(p2p) => {
            let peer_list = p2p.get_peer_list();
            let mut peers = Vec::new();
            let peers_availables = peer_list.get_cloned_peers().await;
            let total_peers = peers_availables.len();
            let mut sharable_peers = 0;
            for p in peers_availables.iter().filter(|p| p.sharable()) {
                peers.push(get_peer_entry(p).await);
                sharable_peers += 1;
            }
            Ok(json!(GetPeersResponse {
                peers,
                total_peers,
                hidden_peers: total_peers - sharable_peers,
            }))
        },
        None => Err(InternalRpcError::InvalidParamsAny(ApiError::NoP2p.into()))
    }
}

async fn get_mempool<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
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

async fn get_estimated_fee_rates<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }

    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let mempool = blockchain.get_mempool().read().await;
    let estimated = mempool.estimate_fee_rates()?;
    Ok(json!(estimated))
}

async fn get_blocks_at_height<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetBlocksAtHeightParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;

    let mut blocks = Vec::new();
    for hash in storage.get_blocks_at_height(params.height).await.context("Error while retrieving blocks at height")? {
        blocks.push(get_block_response_for_hash(&blockchain, &storage, &hash, params.include_txs).await?)
    }
    Ok(json!(blocks))
}

async fn get_tips<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
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
async fn get_dag_order<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
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

fn get_range(start: Option<TopoHeight>, end: Option<TopoHeight>, maximum: u64, current: TopoHeight) -> Result<(TopoHeight, TopoHeight), InternalRpcError> {
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
        return Err(InternalRpcError::InvalidJSONRequest).context(format!("Invalid range requested, start: {}, end: {}", range_start, range_end))?
    }

    let count = range_end - range_start;
    if count > maximum { // only retrieve max 20 blocks hash per request
        debug!("get range requested count: {}", count);
        return Err(InternalRpcError::InvalidJSONRequest).context(format!("Invalid range count requested, received {} but maximum is {}", count, maximum))?
    }

    Ok((range_start, range_end))
}

// get blocks between range of topoheight
// if no params found, get last 20 blocks header
async fn get_blocks_range_by_topoheight<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetTopoHeightRangeParams = parse_params(body)?;

    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let current_topoheight = blockchain.get_topo_height();
    let (start_topoheight, end_topoheight) = get_range(params.start_topoheight, params.end_topoheight, MAX_BLOCKS, current_topoheight)?;

    let storage = blockchain.get_storage().read().await;
    let mut blocks = Vec::with_capacity((end_topoheight - start_topoheight) as usize);
    for i in start_topoheight..=end_topoheight {
        let hash = storage.get_hash_at_topo_height(i).await.context("Error while retrieving hash at topo height")?;
        let response = get_block_response_for_hash(&blockchain, &storage, &hash, false).await?;
        blocks.push(response);
    }

    Ok(json!(blocks))
}

// get blocks between range of height
// if no params found, get last 20 blocks header
// you can only request 
async fn get_blocks_range_by_height<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetHeightRangeParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let current_height = blockchain.get_height();
    let (start_height, end_height) = get_range(params.start_height, params.end_height, MAX_BLOCKS, current_height)?;

    let storage = blockchain.get_storage().read().await;
    let mut blocks = Vec::with_capacity((end_height - start_height) as usize);
    for i in start_height..=end_height {
        let blocks_at_height = storage.get_blocks_at_height(i).await.context("Error while retrieving blocks at height")?;
        for hash in blocks_at_height {
            let response = get_block_response_for_hash(&blockchain, &storage, &hash, false).await?;
            blocks.push(response);
        }
    }

    Ok(json!(blocks))
}

const MAX_TXS: usize = 20;
// get up to 20 transactions at once
// if a tx hash is not present, we keep the order and put json "null" value
async fn get_transactions<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetTransactionsParams = parse_params(body)?;

    let hashes = params.tx_hashes;
    if  hashes.len() > MAX_TXS {
        return Err(InternalRpcError::InvalidJSONRequest).context(format!("Too many requested txs: {}, maximum is {}", hashes.len(), MAX_TXS))?
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
async fn get_account_history<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetAccountHistoryParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    if params.address.is_mainnet() != blockchain.get_network().is_mainnet() {
        return Err(InternalRpcError::InvalidParamsAny(BlockchainError::InvalidNetwork.into()))
    }

    if !params.incoming_flow && !params.outgoing_flow {
        return Err(InternalRpcError::InvalidParams("No history type was selected"));
    }

    let key = params.address.get_public_key();
    let minimum_topoheight = params.minimum_topoheight.unwrap_or(0);
    let storage = blockchain.get_storage().read().await;
    let pruned_topoheight = storage.get_pruned_topoheight().await.context("Error while retrieving pruned topoheight")?.unwrap_or(0);
    let mut version: Option<(u64, Option<u64>, _)> = if let Some(topo) = params.maximum_topoheight {
        if topo < pruned_topoheight {
            return Err(InternalRpcError::InvalidParams("Maximum topoheight is lower than pruned topoheight"));
        }


        // if incoming flows aren't accepted
        // use nonce versions to determine topoheight
        if !params.incoming_flow {
            if let Some((topo, nonce)) = storage.get_nonce_at_maximum_topoheight(key, topo).await.context("Error while retrieving last nonce")? {
                let version = storage.get_balance_at_exact_topoheight(key, &params.asset, topo).await.context(format!("Error while retrieving balance at nonce topo height {topo}"))?;
                Some((topo, nonce.get_previous_topoheight(), version))
            } else {
                None
            }
        } else {
            storage.get_balance_at_maximum_topoheight(key, &params.asset, topo).await
                .context(format!("Error while retrieving balance at topo height {topo}"))?
                .map(|(topo, version)| (topo, None, version))
        }
    } else {
        if !params.incoming_flow {
            // don't return any error, maybe this account never spend anything
            // (even if we force 0 nonce at first activity)
            let (topo, nonce) = storage.get_last_nonce(key).await.context("Error while retrieving last topoheight for nonce")?;
            let version = storage.get_balance_at_exact_topoheight(key, &params.asset, topo).await.context(format!("Error while retrieving balance at topo height {topo}"))?;
            Some((topo, nonce.get_previous_topoheight(), version))
        } else {
            Some(
                storage.get_last_balance(key, &params.asset).await
                    .map(|(topo, version)| (topo, None, version))
                    .context("Error while retrieving last balance")?
            )
        }
    };

    let mut history_count = 0;
    let mut history = Vec::new();

    let is_dev_address = *key == *DEV_PUBLIC_KEY;
    while let Some((topo, prev_nonce, versioned_balance)) = version.take() {
        trace!("Searching history of {} ({}) at topoheight {}, nonce: {:?}, type: {:?}", params.address, params.asset, topo, prev_nonce, versioned_balance.get_balance_type());
        if topo < minimum_topoheight || topo < pruned_topoheight {
            break;
        }

        // Get the block header at topoheight
        // we will scan it below for transactions and rewards
        let (hash, block_header) = storage.get_block_header_at_topoheight(topo).await.context(format!("Error while retrieving block header at topo height {topo}"))?;

        // Block reward is only paid in XELIS
        if params.asset == XELIS_ASSET {
            let is_miner = *block_header.get_miner() == *key;
            if (is_miner || is_dev_address) && params.incoming_flow {
                let mut reward = storage.get_block_reward_at_topo_height(topo).context(format!("Error while retrieving reward at topo height {topo}"))?;
                // subtract dev fee if any
                let dev_fee_percentage = get_block_dev_fee(block_header.get_height());
                if dev_fee_percentage != 0 {
                    let dev_fee = reward * dev_fee_percentage / 100;
                    if is_dev_address {
                        history.push(AccountHistoryEntry {
                            topoheight: topo,
                            hash: hash.clone(),
                            history_type: AccountHistoryType::DevFee { reward: dev_fee },
                            block_timestamp: block_header.get_timestamp()
                        });
                    }
                    reward -= dev_fee;
                }

                if is_miner {
                    let history_type = AccountHistoryType::Mining { reward };
                    history.push(AccountHistoryEntry {
                        topoheight: topo,
                        hash: hash.clone(),
                        history_type,
                        block_timestamp: block_header.get_timestamp()
                    });
                }
            }
        }

        // Reverse the order of transactions to get the latest first
        for tx_hash in block_header.get_transactions().iter().rev() {
            // Don't show unexecuted TXs in the history
            if !storage.is_tx_executed_in_block(tx_hash, &hash)? {
                continue;
            }

            trace!("Searching tx {} in block {}", tx_hash, hash);
            let tx = storage.get_transaction(tx_hash).await.context(format!("Error while retrieving transaction {tx_hash} from block {hash}"))?;
            let is_sender = *tx.get_source() == *key;
            match tx.get_data() {
                TransactionType::Transfers(transfers) => {
                    for transfer in transfers {
                        if *transfer.get_asset() == params.asset {
                            if *transfer.get_destination() == *key && params.incoming_flow {
                                history.push(AccountHistoryEntry {
                                    topoheight: topo,
                                    hash: tx_hash.clone(),
                                    history_type: AccountHistoryType::Incoming {
                                        from: tx.get_source().as_address(blockchain.get_network().is_mainnet())
                                    },
                                    block_timestamp: block_header.get_timestamp()
                                });
                            }

                            if is_sender && params.outgoing_flow {
                                history.push(AccountHistoryEntry {
                                    topoheight: topo,
                                    hash: tx_hash.clone(),
                                    history_type: AccountHistoryType::Outgoing {
                                        to: transfer.get_destination().as_address(blockchain.get_network().is_mainnet())
                                    },
                                    block_timestamp: block_header.get_timestamp()
                                });
                            }
                        }
                    }
                }
                TransactionType::Burn(payload) => {
                    if payload.asset == params.asset {
                        if is_sender && params.outgoing_flow {
                            history.push(AccountHistoryEntry {
                                topoheight: topo,
                                hash: tx_hash.clone(),
                                history_type: AccountHistoryType::Burn { amount: payload.amount },
                                block_timestamp: block_header.get_timestamp()
                            });
                        }
                    }
                },
                TransactionType::MultiSig(payload) => {
                    if is_sender {
                        let mainnet = blockchain.get_network().is_mainnet();
                        history.push(AccountHistoryEntry {
                            topoheight: topo,
                            hash: tx_hash.clone(),
                            history_type: AccountHistoryType::MultiSig {
                                participants: payload.participants.iter().map(|p| p.as_address(mainnet)).collect(),
                                threshold: payload.threshold,
                            },
                            block_timestamp: block_header.get_timestamp()
                        });
                    }
                },
                TransactionType::InvokeContract(payload) => {
                    if is_sender {
                        history.push(AccountHistoryEntry {
                            topoheight: topo,
                            hash: tx_hash.clone(),
                            history_type: AccountHistoryType::InvokeContract {
                                contract: payload.contract.clone(),
                                chunk_id: payload.chunk_id,
                            },
                            block_timestamp: block_header.get_timestamp()
                        });
                    }
                },
                TransactionType::DeployContract(_) => {
                    if is_sender {
                        history.push(AccountHistoryEntry {
                            topoheight: topo,
                            hash: tx_hash.clone(),
                            history_type: AccountHistoryType::DeployContract,
                            block_timestamp: block_header.get_timestamp()
                        });
                    }
                }
            }
        }

        history_count += 1;
        if history_count >= MAX_HISTORY {
            break;
        }

        // if incoming flows aren't accepted
        // use nonce versions to determine topoheight
        if let Some(previous) = prev_nonce.filter(|_| !params.incoming_flow) {
            let nonce_version = storage.get_nonce_at_exact_topoheight(key, previous).await.context(format!("Error while retrieving nonce at topo height {previous}"))?;
            version = Some((previous, nonce_version.get_previous_topoheight(), storage.get_balance_at_exact_topoheight(key, &params.asset, previous).await.context(format!("Error while retrieving previous balance at topo height {previous}"))?));
        } else if let Some(previous) = versioned_balance.get_previous_topoheight().filter(|_| params.incoming_flow) {
            if previous < pruned_topoheight {
                break;
            }

            version = Some((previous, None, storage.get_balance_at_exact_topoheight(key, &params.asset, previous).await.context(format!("Error while retrieving previous balance at topo height {previous}"))?));
        }
    }

    Ok(json!(history))
}

async fn get_account_assets<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetAccountAssetsParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    if params.address.is_mainnet() != blockchain.get_network().is_mainnet() {
        return Err(InternalRpcError::InvalidParamsAny(BlockchainError::InvalidNetwork.into()))
    }

    let key = params.address.get_public_key();
    let storage = blockchain.get_storage().read().await;
    let assets = storage.get_assets_for(key).await.context("Error while retrieving assets for account")?;
    Ok(json!(assets))
}

const MAX_ACCOUNTS: usize = 100;
// retrieve all available accounts (each account got at least one interaction on chain)
async fn get_accounts<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetAccountsParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let topoheight = blockchain.get_topo_height();
    let maximum = if let Some(maximum) = params.maximum {
        if maximum > MAX_ACCOUNTS {
            return Err(InternalRpcError::InvalidJSONRequest).context(format!("Maximum accounts requested cannot be greater than {}", MAX_ACCOUNTS))?
        }
        maximum
    } else {
        MAX_ACCOUNTS
    };
    let skip = params.skip.unwrap_or(0);
    let minimum_topoheight = if let Some(minimum) = params.minimum_topoheight {
        if minimum > topoheight {
            return Err(InternalRpcError::InvalidJSONRequest).context(format!("Minimum topoheight requested cannot be greater than {}", topoheight))?
        }

        minimum
    } else {
        0
    };
    let maximum_topoheight = if let Some(maximum) = params.maximum_topoheight {
        if maximum > topoheight {
            return Err(InternalRpcError::InvalidJSONRequest).context(format!("Maximum topoheight requested cannot be greater than {}", topoheight))?
        }

        if maximum < minimum_topoheight {
            return Err(InternalRpcError::InvalidJSONRequest).context(format!("Maximum topoheight requested must be greater or equal to {}", minimum_topoheight))?
        }
        maximum
    } else {
        topoheight
    };

    let storage = blockchain.get_storage().read().await;
    let mainnet = storage.is_mainnet();
    let accounts = storage.get_registered_keys(maximum, skip, minimum_topoheight, maximum_topoheight).await
        .context("Error while retrieving accounts")?
        .0
        .into_iter().map(|key| key.to_address(mainnet)).collect::<Vec<_>>();

    Ok(json!(accounts))
}

// Check if the account is registered on chain or not
async fn is_account_registered<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: IsAccountRegisteredParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let key = params.address.get_public_key();
    let registered = if params.in_stable_height {
        storage.is_account_registered_for_topoheight(key, blockchain.get_stable_topoheight()).await
            .context("Error while checking if account is registered in stable height")?
    } else {
        storage.is_account_registered(key).await
            .context("Error while checking if account is registered")?
    };

    Ok(json!(registered))
}

// Search the account registration topoheight
async fn get_account_registration_topoheight<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetAccountRegistrationParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let key = params.address.get_public_key();
    let topoheight = storage.get_account_registration_topoheight(key).await.context("Error while retrieving registration topoheight")?;
    Ok(json!(topoheight))
}

// Check if the asked TX is executed in the block
async fn is_tx_executed_in_block<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: IsTxExecutedInBlockParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    Ok(json!(storage.is_tx_executed_in_block(&params.tx_hash, &params.block_hash).context("Error while checking if tx was executed in block")?))
}

// Get the configured dev fees
async fn get_dev_fee_thresholds<S: Storage>(_: &Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }

    Ok(json!(DEV_FEES))
}

// Get size on disk of the chain database
async fn get_size_on_disk<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
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

// Retrieve the mempool cache for an account
async fn get_mempool_cache<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetMempoolCacheParams = parse_params(body)?;
    if !params.address.is_normal() {
        return Err(InternalRpcError::InvalidParamsAny(ApiError::ExpectedNormalAddress.into()))    
    }
    
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    if params.address.is_mainnet() != blockchain.get_network().is_mainnet() {
        return Err(InternalRpcError::InvalidParamsAny(BlockchainError::InvalidNetwork.into()))
    }

    let mempool = blockchain.get_mempool().read().await;
    let cache = mempool.get_cache_for(params.address.get_public_key())
        .context("Account not found while retrieving mempool cache")?;

    Ok(json!(cache))
}

async fn get_difficulty<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }

    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let difficulty = blockchain.get_difficulty().await;
    let hashrate = difficulty / BLOCK_TIME;
    let hashrate_formatted = format_hashrate(hashrate.into());
    Ok(json!(GetDifficultyResult {
        hashrate,
        hashrate_formatted,
        difficulty,
    }))
}

async fn validate_address<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: ValidateAddressParams = parse_params(body)?;

    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    if params.address.is_mainnet() != blockchain.get_network().is_mainnet() {
        return Err(InternalRpcError::InvalidParamsAny(BlockchainError::InvalidNetwork.into()))
    }

    Ok(json!(ValidateAddressResult {
        is_valid: (params.address.is_normal() || (!params.address.is_normal() && params.allow_integrated))
            && params.max_integrated_data_size.and_then(|size| params.address.get_extra_data().map(|data| data.size() <= size))
            .unwrap_or(true),
        is_integrated: !params.address.is_normal(),
    }))
}

async fn extract_key_from_address<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: ExtractKeyFromAddressParams = parse_params(body)?;

    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    if params.address.is_mainnet() != blockchain.get_network().is_mainnet() {
        return Err(InternalRpcError::InvalidParamsAny(BlockchainError::InvalidNetwork.into()))
    }

    if params.as_hex {
        Ok(json!(ExtractKeyFromAddressResult::Hex(params.address.get_public_key().to_hex())))
    } else {
        Ok(json!(ExtractKeyFromAddressResult::Bytes(params.address.get_public_key().to_bytes())))
    }
}

// Split an integrated address into its address and data
async fn split_address<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: SplitAddressParams = parse_params(body)?;
    let address = params.address;

    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    if address.is_mainnet() != blockchain.get_network().is_mainnet() {
        return Err(InternalRpcError::InvalidParamsAny(BlockchainError::InvalidNetwork.into()))
    }

    let (data, address) = address.extract_data();
    let integrated_data = data.ok_or(InternalRpcError::InvalidParams("Address is not an integrated address"))?;
    let size = integrated_data.size();
    Ok(json!(SplitAddressResult {
        address,
        integrated_data,
        size,
    }))
}

async fn make_integrated_address<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: MakeIntegratedAddressParams = parse_params(body)?;

    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    if params.address.is_mainnet() != blockchain.get_network().is_mainnet() {
        return Err(InternalRpcError::InvalidParamsAny(BlockchainError::InvalidNetwork.into()))
    }

    if !params.address.is_normal() {
        return Err(InternalRpcError::InvalidParams("Address is not a normal address"))
    }

    let address = Address::new(params.address.is_mainnet(), AddressType::Data(params.integrated_data.into_owned()), params.address.into_owned().to_public_key());

    Ok(json!(address))
}

async fn decrypt_extra_data<S: Storage>(_: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: DecryptExtraDataParams = parse_params(body)?;
    let data = params.extra_data
        .decrypt_with_shared_key(&params.shared_key)
        .context("Error while decrypting using provided shared key")?;

    Ok(json!(data))
}

async fn get_multisig_at_topoheight<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetMultisigAtTopoHeightParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let multisig = storage.get_multisig_at_topoheight_for(&params.address.get_public_key(), params.topoheight).await
        .context("Error while retrieving multisig at topoheight")?;

    let state = match multisig.take() {
        Some(multisig) => {
            let multisig = multisig.into_owned();
            let mainnet = storage.is_mainnet();
            let participants = multisig.participants.into_iter().map(|p| p.to_address(mainnet)).collect();
            MultisigState::Active {
                    participants,
                    threshold: multisig.threshold,
                }
        },
        None => MultisigState::Deleted
    };

    Ok(json!(GetMultisigAtTopoHeightResult { state }))
}

async fn get_multisig<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetMultisigParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let (topoheight, multisig) = storage.get_last_multisig(&params.address.get_public_key()).await
        .context("Error while retrieving multisig")?;

    let state = match multisig.take() {
        Some(multisig) => {
            let multisig = multisig.into_owned();
            let mainnet = storage.is_mainnet();
            let participants = multisig.participants.into_iter().map(|p| p.to_address(mainnet)).collect();
            MultisigState::Active {
                    participants,
                    threshold: multisig.threshold,
                }
        },
        None => MultisigState::Deleted
    };

    Ok(json!(GetMultisigResult { state, topoheight }))
}

async fn has_multisig<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: HasMultisigParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;

    let multisig = storage.has_multisig(&params.address.get_public_key()).await
            .context("Error while checking if account has multisig")?;

    Ok(json!(multisig))
}

async fn has_multisig_at_topoheight<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: HasMultisigAtTopoHeightParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;

    let multisig = storage.has_multisig_at_topoheight(&params.address.get_public_key(), params.topoheight).await
        .context("Error while checking if account has multisig at topoheight")?;

    Ok(json!(multisig))
}

async fn get_contract_outputs<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetContractOutputsParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let is_mainnet = blockchain.get_network().is_mainnet();
    let storage = blockchain.get_storage().read().await;
    let outputs =  storage.get_contract_outputs_for_tx(&params.transaction).await
        .context("Error while retrieving contract outputs")?;

    let rpc_outputs = outputs
        .iter()
        .map(|output| RPCContractOutput::from_output(&output, is_mainnet))
        .collect::<Vec<_>>();

    Ok(json!(rpc_outputs))
}

async fn get_contract_module<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetContractModuleParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;
    let topoheight = storage.get_last_topoheight_for_contract(&params.contract).await?;
    let module = storage.get_contract_at_topoheight_for(&params.contract, topoheight).await
        .context("Error while retrieving contract module")?;

    Ok(json!(module))
}

async fn get_contract_data<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetContractDataParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;

    let topoheight = storage.get_last_topoheight_for_contract_data(&params.contract, &params.key).await
        .context("Error while retrieving last topoheight for contract data")?;

    let version = storage.get_contract_data_at_topoheight_for(&params.contract, &params.key, topoheight).await?;

    Ok(json!(RPCVersioned {
        topoheight,
        version,
    }))
}


async fn get_contract_data_at_topoheight<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetContractDataAtTopoHeightParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;

    let version = storage.get_contract_data_at_topoheight_for(&params.contract, &params.key, params.topoheight).await?;

    Ok(json!(version))
}

async fn get_contract_balance<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetContractBalanceParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;

    let (topoheight, version) = storage.get_last_contract_balance(&params.contract, &params.asset).await
        .context("Error while retrieving contract balance")?;

    Ok(json!(RPCVersioned {
        topoheight,
        version,
    }))
}

async fn get_contract_balance_at_topoheight<S: Storage>(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetContractBalanceAtTopoHeightParams = parse_params(body)?;
    let blockchain: &Arc<Blockchain<S>> = context.get()?;
    let storage = blockchain.get_storage().read().await;

    let version = storage.get_contract_balance_at_exact_topoheight(&params.contract, &params.asset, params.topoheight).await
        .context("Error while retrieving contract balance")?;

    Ok(json!(version))
}