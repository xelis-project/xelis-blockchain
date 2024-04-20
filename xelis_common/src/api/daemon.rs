use std::{
    borrow::Cow,
    collections::{HashSet, HashMap},
    net::SocketAddr
};
use indexmap::IndexSet;
use serde::{Deserialize, Serialize, Serializer, Deserializer, de::Error};
use crate::{
    account::{CiphertextCache, VersionedBalance, VersionedNonce},
    block::EXTRA_NONCE_SIZE,
    crypto::{Address, Hash},
    difficulty::{CumulativeDifficulty, Difficulty},
    network::Network,
    time::{TimestampMillis, TimestampSeconds}
};
use super::RPCTransaction;

#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub enum BlockType {
    Sync,
    Side,
    Orphaned,
    Normal
}

// Serialize the extra nonce in a hexadecimal string
pub fn serialize_extra_nonce<S: Serializer>(extra_nonce: &Cow<'_, [u8; EXTRA_NONCE_SIZE]>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&hex::encode(extra_nonce.as_ref()))
}

// Deserialize the extra nonce from a hexadecimal string
pub fn deserialize_extra_nonce<'de, 'a, D: Deserializer<'de>>(deserializer: D) -> Result<Cow<'a, [u8; EXTRA_NONCE_SIZE]>, D::Error> {
    let mut extra_nonce = [0u8; EXTRA_NONCE_SIZE];
    let hex = String::deserialize(deserializer)?;
    let decoded = hex::decode(hex).map_err(Error::custom)?;
    extra_nonce.copy_from_slice(&decoded);
    Ok(Cow::Owned(extra_nonce))
}

// Structure used to map the public key to a human readable address
#[derive(Serialize, Deserialize)]
pub struct RPCBlockResponse<'a> {
    pub hash: Cow<'a, Hash>,
    pub topoheight: Option<u64>,
    pub block_type: BlockType,
    pub difficulty: Cow<'a, Difficulty>,
    pub supply: Option<u64>,
    pub reward: Option<u64>,
    pub cumulative_difficulty: Cow<'a, CumulativeDifficulty>,
    pub total_fees: Option<u64>,
    pub total_size_in_bytes: usize,
    pub version: u8,
    pub tips: Cow<'a, IndexSet<Hash>>,
    pub timestamp: TimestampMillis,
    pub height: u64,
    pub nonce: u64,
    #[serde(serialize_with = "serialize_extra_nonce")]
    #[serde(deserialize_with = "deserialize_extra_nonce")]
    pub extra_nonce: Cow<'a, [u8; EXTRA_NONCE_SIZE]>,
    pub miner: Cow<'a, Address>,
    pub txs_hashes: Cow<'a, IndexSet<Hash>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub transactions: Vec<RPCTransaction<'a>>,
}

pub type BlockResponse = RPCBlockResponse<'static>;

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
    pub address: Cow<'a, Address>
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
    pub address: Cow<'a, Address>,
    pub asset: Cow<'a, Hash>
}


#[derive(Serialize, Deserialize)]
pub struct HasBalanceParams<'a> {
    pub address: Cow<'a, Address>,
    pub asset: Cow<'a, Hash>,
    #[serde(default)]
    pub topoheight: Option<u64>
}

#[derive(Serialize, Deserialize)]
pub struct HasBalanceResult {
    pub exist: bool
}

#[derive(Serialize, Deserialize)]
pub struct GetBalanceAtTopoHeightParams<'a> {
    pub address: Cow<'a, Address>,
    pub asset: Cow<'a, Hash>,
    pub topoheight: u64
}

#[derive(Serialize, Deserialize)]
pub struct GetNonceParams<'a> {
    pub address: Cow<'a, Address>
}

#[derive(Serialize, Deserialize)]
pub struct HasNonceParams<'a> {
    pub address: Cow<'a, Address>,
    #[serde(default)]
    pub topoheight: Option<u64>
}

#[derive(Serialize, Deserialize)]
pub struct GetNonceAtTopoHeightParams<'a> {
    pub address: Cow<'a, Address>,
    pub topoheight: u64
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
pub struct GetBalanceResult {
    pub version: VersionedBalance,
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

// Direction is used for cache to knows from which context it got added
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    // We don't update it because it's In, we won't send back
    In,
    // Out can be updated with In to be transformed to Both
    // Because of desync, we may receive the object while sending it
    Out,
    // Cannot be updated
    Both
}

impl Direction {
    pub fn update(&mut self, direction: Direction) -> bool {
        match self {
            Self::Out => match direction {
                Self::In => {
                    *self = Self::Both;
                    true
                },
                _ => false
            },
            Self::In => match direction {
                Self::Out => {
                    *self = Self::Both;
                    true
                },
                _ => false
            },
            _ => false
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct GetPeersResponse<'a> {
    // Peers that are connected and allows to be displayed
    pub peers: Vec<PeerEntry<'a>>,
    // All peers connected
    pub total_peers: usize,
    // Peers that asked to not be listed
    pub hidden_peers: usize
}

#[derive(Serialize, Deserialize)]
pub struct PeerEntry<'a> {
    pub id: u64,
    pub addr: Cow<'a, SocketAddr>,
    pub local_port: u16,
    pub tag: Cow<'a, Option<String>>,
    pub version: Cow<'a, String>,
    pub top_block_hash: Cow<'a, Hash>,
    pub topoheight: u64,
    pub height: u64,
    pub last_ping: TimestampSeconds,
    pub pruned_topoheight: Option<u64>,
    pub peers: Cow<'a, HashMap<SocketAddr, Direction>>,
    pub cumulative_difficulty: Cow<'a, CumulativeDifficulty>,
    pub connected_on: TimestampSeconds
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
pub struct TransactionResponse<'a> {
    // in which blocks it was included
    pub blocks: Option<HashSet<Hash>>,
    // in which blocks it was executed
    pub executed_in_block: Option<Hash>,
    // if it is in mempool
    pub in_mempool: bool,
    // if its a mempool tx, we add the timestamp when it was added
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub first_seen: Option<TimestampSeconds>,
    #[serde(flatten)]
    pub data: RPCTransaction<'a>
}

fn default_xelis_asset() -> Hash {
    crate::config::XELIS_ASSET
}

#[derive(Serialize, Deserialize)]
pub struct GetAccountHistoryParams {
    pub address: Address,
    #[serde(default = "default_xelis_asset")]
    pub asset: Hash,
    pub minimum_topoheight: Option<u64>,
    pub maximum_topoheight: Option<u64>
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")] 
pub enum AccountHistoryType {
    DevFee { reward: u64 },
    Mining { reward: u64 },
    Burn { amount: u64 },
    Outgoing { to: Address },
    Incoming { from: Address },
}

#[derive(Serialize, Deserialize)]
pub struct AccountHistoryEntry {
    pub topoheight: u64,
    pub hash: Hash,
    #[serde(flatten)]
    pub history_type: AccountHistoryType,
    pub block_timestamp: TimestampMillis
}

#[derive(Serialize, Deserialize)]
pub struct GetAccountAssetsParams<'a> {
    pub address: Cow<'a, Address>
}

#[derive(Serialize, Deserialize)]
pub struct GetAssetParams<'a> {
    pub asset: Cow<'a, Hash>
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
pub struct IsAccountRegisteredParams<'a> {
    pub address: Cow<'a, Address>,
    // If it is registered in stable height (confirmed)
    pub in_stable_height: bool,
}

#[derive(Serialize, Deserialize)]
pub struct GetAccountRegistrationParams<'a> {
    pub address: Cow<'a, Address>,
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

#[derive(Serialize, Deserialize)]
pub struct GetMempoolCacheParams<'a> {
    pub address: Cow<'a, Address>
}

#[derive(Serialize, Deserialize)]
pub struct GetMempoolCacheResult {
    // lowest nonce used
    min: u64,
    // highest nonce used
    max: u64,
    // all txs ordered by nonce
    txs: Vec<Hash>,
    // All "final" cached balances used
    balances: HashMap<Hash, CiphertextCache>
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotifyEvent {
    // When a new block is accepted by chain
    // it contains NewBlockEvent as value
    NewBlock,
    // When a block (already in chain or not) is ordered (new topoheight)
    // it contains BlockOrderedEvent as value
    BlockOrdered,
    // When a block that was ordered is not in the new DAG order
    // it contains BlockOrphanedEvent that got orphaned
    BlockOrphaned,
    // When stable height has changed (different than the previous one)
    // it contains StableHeightChangedEvent struct as value
    StableHeightChanged,
    // When a transaction that was executed in a block is not reintroduced in mempool
    // It contains TransactionOrphanedEvent as value
    TransactionOrphaned,
    // When a new transaction is added in mempool
    // it contains TransactionAddedInMempoolEvent struct as value
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
    // It contains PeerConnectedEvent struct as value
    PeerConnected,
    // When a peer has disconnected from us
    // It contains PeerDisconnectedEvent struct as value
    PeerDisconnected,
    // Peer peerlist updated, its all its connected peers
    // It contains PeerPeerListUpdatedEvent as value
    PeerPeerListUpdated,
    // Peer has been updated through a ping packet
    // Contains PeerStateUpdatedEvent as value
    PeerStateUpdated,
    // When a peer of a peer has disconnected
    // and that he notified us
    // It contains PeerPeerDisconnectedEvent as value
    PeerPeerDisconnected,
}

// Value of NotifyEvent::NewBlock
pub type NewBlockEvent = BlockResponse;

// Value of NotifyEvent::BlockOrdered
#[derive(Serialize, Deserialize)]
pub struct BlockOrderedEvent<'a> {
    // block hash in which this event was triggered
    pub block_hash: Cow<'a, Hash>,
    pub block_type: BlockType,
    // the new topoheight of the block
    pub topoheight: u64,
}

// Value of NotifyEvent::BlockOrphaned
#[derive(Serialize, Deserialize)]
pub struct BlockOrphanedEvent<'a> {
    pub block_hash: Cow<'a, Hash>,
    // Tpoheight of the block before being orphaned
    pub old_topoheight: u64
}

// Value of NotifyEvent::StableHeightChanged
#[derive(Serialize, Deserialize)]
pub struct StableHeightChangedEvent {
    pub previous_stable_height: u64,
    pub new_stable_height: u64
}

// Value of NotifyEvent::TransactionAddedInMempool
pub type TransactionAddedInMempoolEvent = TransactionResponse<'static>;
// Value of NotifyEvent::TransactionOrphaned
pub type TransactionOrphanedEvent = TransactionResponse<'static>;

// Value of NotifyEvent::TransactionExecuted
#[derive(Serialize, Deserialize)]
pub struct TransactionExecutedEvent<'a> {
    pub block_hash: Cow<'a, Hash>,
    pub tx_hash: Cow<'a, Hash>,
    pub topoheight: u64,
}

// Value of NotifyEvent::PeerConnected
pub type PeerConnectedEvent = PeerEntry<'static>;

// Value of NotifyEvent::PeerDisconnected
pub type PeerDisconnectedEvent = PeerEntry<'static>;

// Value of NotifyEvent::PeerPeerListUpdated
#[derive(Serialize, Deserialize)]
pub struct PeerPeerListUpdatedEvent {
    // Peer ID of the peer that sent us the new peer list
    pub peer_id: u64,
    // Peerlist received from this peer
    pub peerlist: Vec<SocketAddr>
}

// Value of NotifyEvent::PeerStateUpdated
pub type PeerStateUpdatedEvent = PeerEntry<'static>;

// Value of NotifyEvent::PeerPeerDisconnected
#[derive(Serialize, Deserialize)]
pub struct PeerPeerDisconnectedEvent {
    // Peer ID of the peer that sent us this notification
    pub peer_id: u64,
    // address of the peer that disconnected from him
    pub peer_addr: SocketAddr
}