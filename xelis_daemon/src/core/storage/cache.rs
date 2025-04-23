use xelis_common::block::TopoHeight;

use super::Tips;

#[derive(Debug, Default, Clone)]
pub struct StorageCache {
    // Count of assets
    pub assets_count: u64,
    // Count of accounts
    pub accounts_count: u64,
    // Count of transactions
    pub transactions_count: u64,
    // Count of blocks
    pub blocks_count: u64,
    // Count of blocks added in chain
    pub blocks_execution_count: u64,
    // Count of contracts
    pub contracts_count: u64,
    // Tips cache
    pub tips_cache: Tips,
    // Pruned topoheight cache
    pub(super) pruned_topoheight: Option<TopoHeight>
}