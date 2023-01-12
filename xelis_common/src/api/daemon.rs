use serde::{Deserialize, Serialize};

use crate::crypto::{hash::Hash, address::Address};

#[derive(Serialize)]
pub struct DataHash<T> {
    pub hash: Hash,
    #[serde(flatten)]
    pub data: T
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
    pub topoheight: Option<u64>,
    pub block_type: BlockType,
    pub difficulty: u64,
    pub supply: u64,
    pub reward: u64,
    pub cumulative_difficulty: u64,
    #[serde(flatten)]
    pub data: DataHash<T>
}

#[derive(Serialize, Deserialize)]
pub struct GetBlockAtTopoHeightParams {
    pub topoheight: u64
}

#[derive(Serialize, Deserialize)]
pub struct GetBlocksAtHeightParams {
    pub height: u64
}

#[derive(Serialize, Deserialize)]
pub struct GetBlockByHashParams {
    pub hash: Hash
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
}

#[derive(Serialize, Deserialize)]
pub struct GetMessagesParams<'a> {
    pub address: Address<'a>,
    pub from: Option<Address<'a>>
}

#[derive(Serialize, Deserialize)]
pub struct GetBalanceParams<'a> {
    pub address: Address<'a>,
    pub asset: Hash
}

#[derive(Serialize, Deserialize)]
pub struct GetNonceParams<'a> {
    pub address: Address<'a>,
}

#[derive(Serialize, Deserialize)]
pub struct SubmitTransactionParams {
    pub data: String // should be in hex format
}

#[derive(Serialize, Deserialize)]
pub struct GetTransactionParams {
    pub hash: Hash
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