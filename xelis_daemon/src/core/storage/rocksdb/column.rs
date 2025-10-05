use strum::{Display, EnumIter, AsRefStr};

const PREFIX_TOPOHEIGHT_LEN: usize = 8;
const PREFIX_ID_LEN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Hash, EnumIter, Display, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum Column {
    // All transactions stored
    // {tx_hash} => {transaction}
    Transactions,
    // Which TXs are marked as executed
    // {tx_hash} => {block_hash}
    TransactionsExecuted,
    // In which blocks this TX was included
    // {tx_hash} => {block_hashes}
    TransactionInBlocks,
    // Transaction contract outputs
    // Standardized events that occurs on a contract call
    // {tx_hash} => {outputs}
    TransactionsOutputs,

    // ordered blocks hashes based on execution
    // {position} => {block_hash}
    BlocksExecutionOrder,
    // All blocks stored
    // {block_hash} => {block}
    Blocks,
    // All blocks hashes stored per height
    // {height} => {block_hashes}
    BlocksAtHeight,
    // Topoheight for a block hash
    // {block_hash} => {topoheight}
    TopoByHash,
    // Hash at a topoheight
    // {topoheight} => {block_hash}
    HashAtTopo,
    // Block difficulty / cumulative difficulty / covariance / ema size
    // {block_hash} => {metadata}
    BlockMetadata,
    // Misc data with no specific rules
    Common,
    // Topoheight Metadata
    // {topoheight} => {metadata}
    TopoHeightMetadata,

    // Each asset hash registered
    // {asset_hash} => {asset}
    Assets,
    // {asset_id} => {asset_hash}
    AssetById,
    // {topoheight}{asset_hash} => {asset}
    VersionedAssets,

    // {account_key} => {account}
    Account,
    // Column used as a "versioned" as its 
    // prefixed with a topoheight to have
    // easier search per topoheight
    // {topoheight}{account_key} => {}
    PrefixedRegistrations,
    // This column is used as a reverse index
    // {account_id} => {account_key}
    AccountById,

    // {topoheight}{account_id} => {version}
    VersionedMultisig,
    // {topoheight}{account_id} => {version}
    VersionedNonces,

    // Account balances pointer
    // {account_id}{asset_id} => {topoheight}
    Balances,
    // {topoheight}{account_id}{asset_id} => {version}
    VersionedBalances,

    // Contains the contract module per hash
    // {contract_hash} => {contract}
    Contracts,
    // {contract_id} => {contract_hash}
    ContractById,

    // This index is generalized, and not contract-dependent
    // So we may have unused values in it
    // Contains the storage key used in a contract
    // We map it to a u64
    // We don't store a reverse index because we can't delete
    // this one, we may never know if its still used or not
    // {key} => {contract_data_id}
    ContractDataTable,
    // {contract_data_id} => {key}
    ContractDataTableById,

    // {topoheight}{contract_id} => {version}
    VersionedContracts,
    // Represent the link between a contract and a data stored
    // in its storage part
    // {contract_id}{contract_data_id} => {topoheight}
    ContractsData,
    // {topoheight}{contract_id}{contract_data_id} => {version}
    VersionedContractsData,

    // {topoheight}{contract_id}
    DelayedExecution,

    // {contract}{asset} => {topoheight}
    ContractsBalances,
    // {topoheight}{contract}{asset} => {version}
    VersionedContractsBalances,

    // {topoheight}{asset_id} => {version}
    VersionedAssetsSupply
}

impl Column {
    pub const fn prefix(&self) -> Option<usize> {
        use Column::*;

        match self {
            VersionedAssets
            | VersionedNonces
            | VersionedBalances
            | VersionedMultisig
            | VersionedAssetsSupply
            | VersionedContracts
            | VersionedContractsBalances
            | VersionedContractsData
            | PrefixedRegistrations
            // Special case: prefixed with topoheight too
            | DelayedExecution => Some(PREFIX_TOPOHEIGHT_LEN),

            ContractsBalances
            | ContractsData
            | Balances => Some(PREFIX_ID_LEN),

            _ => None,
        }
    }
}