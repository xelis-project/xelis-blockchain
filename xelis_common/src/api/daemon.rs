use std::{borrow::Cow, collections::HashSet, net::SocketAddr};

use serde::{Deserialize, Serialize};

use crate::{crypto::{hash::Hash, address::Address, key::PublicKey}, account::{VersionedBalance, VersionedNonce}, network::Network, block::Difficulty, transaction::Transaction};

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
pub struct HasNonceParams<'a> {
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
pub struct HasNonceResult {
    pub exist: bool
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
    pub top_block_hash: Hash,
    // Current XELIS circulating supply
    pub circulating_supply: u64,
    // Maximum supply of XELIS
    pub maximum_supply: u64,
    // Current difficulty at tips
    pub difficulty: Difficulty,
    // Expected block time
    pub block_time_target: u64,
    // Average block time of last 50 blocks
    pub average_block_time: u64,
    pub block_reward: u64,
    // count how many transactions are present in mempool
    pub mempool_size: usize,
    // software version on which the daemon is running
    pub version: String,
    // Network state (mainnet, testnet, devnet)
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
pub struct PeerEntry<'a> {
    pub id: u64,
    pub addr: Cow<'a, SocketAddr>,
    pub tag: Cow<'a, Option<String>>,
    pub version: Cow<'a, String>,
    pub top_block_hash: Hash,
    pub topoheight: u64,
    pub height: u64,
    pub last_ping: u64,
    pub pruned_topoheight: Option<u64>,
    pub peers: HashSet<SocketAddr>,
    pub cumulative_difficulty: Difficulty
}

#[derive(Serialize, Deserialize)]
pub struct P2pStatusResult<'a> {
    pub peer_count: usize,
    pub max_peers: usize,
    pub tag: Cow<'a, Option<String>>,
    pub our_topoheight: u64,
    pub best_topoheight: u64,
    pub median_topoheight: u64,
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
pub struct TransactionResponse<'a, T: Clone + AsRef<Transaction>> {
    // in which blocks it was included
    pub blocks: Option<HashSet<Hash>>,
    // in which blocks it was executed
    pub executed_in_block: Option<Hash>,
    // if it is in mempool
    pub in_mempool: bool,
    // if its a mempool tx, we add the timestamp when it was added
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub first_seen: Option<u64>,
    #[serde(flatten)]
    pub data: DataHash<'a, T>
}

fn default_xelis_asset() -> Hash {
    crate::config::XELIS_ASSET
}

#[derive(Serialize, Deserialize)]
pub struct GetAccountHistoryParams<'a> {
    pub address: Address<'a>,
    #[serde(default = "default_xelis_asset")]
    pub asset: Hash,
    pub minimum_topoheight: Option<u64>,
    pub maximum_topoheight: Option<u64>
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")] 
pub enum AccountHistoryType {
    Mining { reward: u64 },
    Burn { amount: u64 },
    // TODO delete those two fields with upcoming privacy layer
    Outgoing { amount: u64 },
    Incoming { amount: u64, from: PublicKey },
}

#[derive(Serialize, Deserialize)]
pub struct AccountHistoryEntry {
    pub topoheight: u64,
    pub hash: Hash,
    #[serde(flatten)]
    pub history_type: AccountHistoryType,
    pub block_timestamp: u128
}

#[derive(Serialize, Deserialize)]
pub struct GetAccountAssetsParams<'a> {
    pub address: Address<'a>,
}

#[derive(Serialize, Deserialize)]
pub struct GetAssetParams {
    pub asset: Hash
}

#[derive(Serialize, Deserialize)]
pub struct GetAssetsParams {
    pub skip: Option<usize>,
    pub maximum: Option<usize>,
    pub minimum_topoheight: Option<u64>,
    pub maximum_topoheight: Option<u64>
}

#[derive(Serialize, Deserialize)]
pub struct GetAccountsParams {
    pub skip: Option<usize>,
    pub maximum: Option<usize>,
    pub minimum_topoheight: Option<u64>,
    pub maximum_topoheight: Option<u64>
}

#[derive(Serialize, Deserialize)]
pub struct IsTxExecutedInBlockParams<'a> {
    pub tx_hash: Cow<'a, Hash>,
    pub block_hash: Cow<'a, Hash>
}

// Struct to define dev fee threshold
#[derive(serde::Serialize, serde::Deserialize)]
pub struct DevFeeThreshold {
    // block height to start dev fee
    pub height: u64,
    // percentage of dev fee, example 10 = 10%
    pub fee_percentage: u64
}

// Struct to returns the size of the blockchain on disk
#[derive(Serialize, Deserialize)]
pub struct SizeOnDiskResult {
    pub size_bytes: u64,
    pub size_formatted: String
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    NewAsset,
    // When a new peer has connected to us
    // It contains PeerEntry struct as value
    PeerConnected,
    // When a peer has disconnected from us
    // It contains peer id as value
    // TODO not implemented yet
    PeerDisconnected,
    // Peer peerlist updated, its all its connected peers
    // It contains PeerPeerListUpdatedEvent as value
    PeerPeerListUpdated,
    // Peer has been updated through a ping packet
    PeerStateUpdated,
    // When a peer of a peer has disconnected
    // and that he notified us
    // It contains PeerPeerDisconnectedEvent as value
    PeerPeerDisconnected,
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

#[derive(Serialize, Deserialize)]
pub struct PeerPeerListUpdatedEvent {
    // Peer ID of the peer that sent us the new peer list
    pub peer_id: u64,
    // Peerlist received from this peer
    pub peerlist: Vec<SocketAddr>
}

#[derive(Serialize, Deserialize)]
pub struct PeerPeerDisconnectedEvent {
    // Peer ID of the peer that sent us this notification
    pub peer_id: u64,
    // address of the peer that disconnected from him
    pub peer_addr: SocketAddr
}