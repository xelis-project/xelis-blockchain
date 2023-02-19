use std::borrow::Cow;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{crypto::{hash::Hash, address::Address}, account::VersionedBalance};

#[derive(Serialize, Deserialize)]
pub struct DataHash<'a, T: Clone> {
    pub hash: Cow<'a, Hash>,
    #[serde(flatten)]
    pub data: Cow<'a, T>
}

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
    pub difficulty: u64,
    pub supply: u64,
    pub reward: u64,
    pub cumulative_difficulty: u64,
    pub total_fees: u64,
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
    pub template: String,
    pub difficulty: u64
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
    pub top_hash: Hash,
    pub native_supply: u64,
    pub difficulty: u64,
    pub block_time_target: u64,
    // count how many transactions are present in mempool
    pub mempool_size: usize,
    pub version: String
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
pub struct GetRangeParams {
    pub start_topoheight: Option<u64>,
    pub end_topoheight: Option<u64>
}


#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NotifyEvent {
    // When a new block is accepted by chain
    NewBlock,
    // When a new transaction is added in mempool
    TransactionAddedInMempool,
    // When a transaction has been included in a valid block & executed on chain
    TransactionExecuted,
    // When a registered TX SC Call hash has been executed by chain
    TransactionSCResult,
    // When a new asset has been registered
    NewAsset
}

#[derive(Serialize, Deserialize)]
pub struct EventResult {
    pub event: NotifyEvent,
    #[serde(flatten)]
    pub value: Value
}