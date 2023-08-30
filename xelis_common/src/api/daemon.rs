use std::{borrow::Cow, collections::HashSet};

use serde::{Deserialize, Serialize};

use crate::{crypto::{hash::Hash, address::Address}, account::{VersionedBalance, VersionedNonce}, network::Network, block::Difficulty};

use super::DataHash;

#[derive(Serialize, Deserialize)]
pub enum BlockType {
    Sync,
    Side,
    Orphaned,
    Normal
}

#[derive(Serialize, Deserialize)]
pub struct BlockResponse<'a, T: Clone> {
    pub topoheight: Option<u64>,
    pub block_type: BlockType,
    pub difficulty: Difficulty,
    pub supply: Option<u64>,
    pub reward: Option<u64>,
    pub cumulative_difficulty: Difficulty,
    pub total_fees: Option<u64>,
    pub total_size_in_bytes: usize,
    #[serde(flatten)]
    pub data: DataHash<'a, T>
}

#[derive(Serialize, Deserialize)]
pub struct GetTopBlockParams {
    #[serde(default)]
    pub include_txs: bool
}

#[derive(Serialize, Deserialize)]
pub struct GetBlockAtTopoHeightParams {
    pub topoheight: u64,
    #[serde(default)]
    pub include_txs: bool
}

#[derive(Serialize, Deserialize)]
pub struct GetBlocksAtHeightParams {
    pub height: u64,
    #[serde(default)]
    pub include_txs: bool
}

#[derive(Serialize, Deserialize)]
pub struct GetBlockByHashParams<'a> {
    pub hash: Cow<'a, Hash>,
    #[serde(default)]
    pub include_txs: bool
}

#[derive(Serialize, Deserialize)]
pub struct GetBlockTemplateParams<'a> {
    pub address: Cow<'a, Address<'a>>
}

#[derive(Serialize, Deserialize, PartialEq)]
pub struct GetBlockTemplateResult {
    pub template: String, // template is BlockMiner in hex format
    pub height: u64, // block height
    pub difficulty: Difficulty // difficulty required for valid block
}

#[derive(Serialize, Deserialize)]
pub struct SubmitBlockParams {
    pub block_template: String, // hex: represent the BlockHeader (Block)
}

#[derive(Serialize, Deserialize)]
pub struct GetMessagesParams<'a> {
    pub address: Address<'a>,
    pub from: Option<Address<'a>>
}

#[derive(Serialize, Deserialize)]
pub struct GetBalanceParams<'a> {
    pub address: Cow<'a, Address<'a>>,
    pub asset: Cow<'a, Hash>
}

#[derive(Serialize, Deserialize)]
pub struct GetBalanceAtTopoHeightParams<'a> {
    pub address: Cow<'a, Address<'a>>,
    pub asset: Cow<'a, Hash>,
    pub topoheight: u64
}

#[derive(Serialize, Deserialize)]
pub struct GetNonceParams<'a> {
    pub address: Cow<'a, Address<'a>>,
    #[serde(default)]
    pub topoheight: Option<u64>
}

#[derive(Serialize, Deserialize)]
pub struct GetNonceResult {
    pub topoheight: u64,
    #[serde(flatten)]
    pub version: VersionedNonce
}

#[derive(Serialize, Deserialize)]
pub struct GetLastBalanceResult {
    pub balance: VersionedBalance,
    pub topoheight: u64
}

#[derive(Serialize, Deserialize)]
pub struct GetInfoResult {
    pub height: u64,
    pub topoheight: u64,
    pub stableheight: u64,
    pub pruned_topoheight: Option<u64>,
    pub top_hash: Hash,
    pub native_supply: u64,
    pub difficulty: Difficulty,
    pub block_time_target: u64,
    pub average_block_time: u64,
    pub block_reward: u64,
    // count how many transactions are present in mempool
    pub mempool_size: usize,
    pub version: String,
    pub network: Network
}

#[derive(Serialize, Deserialize)]
pub struct SubmitTransactionParams {
    pub data: String // should be in hex format
}

#[derive(Serialize, Deserialize)]
pub struct GetTransactionParams<'a> {
    pub hash: Cow<'a, Hash>
}

#[derive(Serialize, Deserialize)]
pub struct P2pStatusResult<'a> {
    pub peer_count: usize,
    pub max_peers: usize,
    pub tag: Cow<'a, Option<String>>,
    pub our_topoheight: u64,
    pub best_topoheight: u64,
    pub peer_id: u64
}

#[derive(Serialize, Deserialize)]
pub struct GetTopoHeightRangeParams {
    pub start_topoheight: Option<u64>,
    pub end_topoheight: Option<u64>
}

#[derive(Serialize, Deserialize)]
pub struct GetHeightRangeParams {
    pub start_height: Option<u64>,
    pub end_height: Option<u64>
}

#[derive(Serialize, Deserialize)]
pub struct GetTransactionsParams {
    pub tx_hashes: Vec<Hash>
}

#[derive(Serialize, Deserialize)]
pub struct TransactionResponse<'a, T: Clone> {
    // in which blocks it was included
    pub blocks: Option<HashSet<Hash>>,
    // in which blocks it was executed
    pub executed_in_block: Option<Hash>,
    // if it is in mempool
    pub in_mempool: bool,
    #[serde(flatten)]
    pub data: DataHash<'a, T>
}

#[derive(Serialize, Deserialize)]
pub struct GetAssetsParams {
    pub skip: Option<usize>,
    pub maximum: Option<usize>,
    pub minimum_topoheight: Option<u64>,
    pub maximum_topoheight: Option<u64>
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NotifyEvent {
    // When a new block is accepted by chain
    // it contains Block struct as value
    NewBlock,
    // When a block (already in chain or not) is ordered (new topoheight)
    // it contains BlockOrderedEvent as value
    BlockOrdered,
    // When stable height has changed (different than the previous one)
    // it contains StableHeightChangedEvent struct as value
    StableHeightChanged,
    // When a new transaction is added in mempool
    // it contains Transaction struct as value
    TransactionAddedInMempool,
    // When a transaction has been included in a valid block & executed on chain
    // it contains TransactionExecutedEvent struct as value
    TransactionExecuted,
    // When a registered TX SC Call hash has been executed by chain
    // TODO: Smart Contracts
    TransactionSCResult,
    // When a new asset has been registered
    // TODO: Smart Contracts
    NewAsset
}

#[derive(Serialize, Deserialize)]
pub struct BlockOrderedEvent<'a> {
    // block hash in which this event was triggered
    pub block_hash: Cow<'a, Hash>,
    pub block_type: BlockType,
    // the new topoheight of the block
    pub topoheight: u64,
}

#[derive(Serialize, Deserialize)]
pub struct StableHeightChangedEvent {
    pub previous_stable_height: u64,
    pub new_stable_height: u64
}

#[derive(Serialize, Deserialize)]
pub struct TransactionExecutedEvent<'a> {
    pub block_hash: Cow<'a, Hash>,
    pub tx_hash: Cow<'a, Hash>,
    pub topoheight: u64,
}