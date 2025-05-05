use strum::{Display, EnumIter};
use xelis_common::crypto::{elgamal::RISTRETTO_COMPRESSED_SIZE, HASH_SIZE};

const PREFIX_TOPOHEIGHT_LEN: usize = 8;
const PREFIX_ACCOUNT_LEN: usize = RISTRETTO_COMPRESSED_SIZE;
const PREFIX_ASSET_LEN: usize = HASH_SIZE;

#[derive(Debug, Clone, Copy, EnumIter, Display)]
#[strum(serialize_all = "snake_case")]
pub enum Column {
    // All transactions stored
    Transactions,
    // Which TXs are marked as executed
    TransactionsExecuted,
    // In which blocks this TX was included
    TransactionInBlocks,
    // ordered blocks hashes based on execution
    BlocksExecutionOrder,
    // All blocks stored
    Blocks,
    // All blocks hashes stored per height
    BlocksAtHeight,
    // Topoheight for a block hash
    TopoByHash,
    // Hash at a topoheight
    HashAtTopo,
    // Block difficulty / cumulative difficulty / covariance
    BlockDifficulty,
    // Misc data with no specific rules
    Common,
    // Topoheight Metadata
    TopoHeightMetadata,

    // Each asset hash registered
    Assets,
    VersionedAssets,

    // {account_key} => {Account}
    Account,
    // {account_id} => {account_key}
    AccountById,

    // {topoheight}{account_id}
    VersionedMultisig,
    // {topoheight}{account_id}
    VersionedNonces,

    // Account balances pointer
    // {account_id}{asset}
    Balances,
    // {topoheight}{account_id}{asset}
    VersionedBalances,

    // {contract}
    Contracts,
    // {topoheight}{contract}
    VersionedContracts,

    // {contract}{asset}
    ContractsBalances,
    // {topoheight}{contract}{asset}
    VersionedContractsBalances,

    // {asset}
    AssetsSupply,
    // {topoheight}{asset}
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
            | VersionedContractsBalances => Some(PREFIX_TOPOHEIGHT_LEN),

            ContractsBalances => Some(PREFIX_ASSET_LEN),
            Balances => Some(PREFIX_ACCOUNT_LEN),

            _ => None,
        }
    }
}