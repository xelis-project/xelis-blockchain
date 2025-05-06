use crate::p2p::error::P2pError;
use std::sync::PoisonError;
use strum::{EnumDiscriminants, IntoDiscriminant};
use thiserror::Error;
use xelis_common::{
    crypto::{
        bech32::Bech32Error,
        elgamal::DecompressionError,
        proofs::ProofVerificationError,
        Address,
        Hash,
        XelisHashError
    },
    account::Nonce,
    block::TopoHeight,
    difficulty::DifficultyError,
    prompt::PromptError,
    rpc_server::InternalRpcError,
    serializer::ReaderError,
    time::TimestampMillis,
    transaction::verify::VerificationError,
    utils::format_xelis
};
use human_bytes::human_bytes;

#[derive(Error, Debug, Clone, Copy)]
pub enum DiskContext {
    #[error("data len")]
    DataLen,
    #[error("multisig")]
    Multisig,
    #[error("get multisig at topoheight {0}")]
    MultisigAtTopoHeight(TopoHeight),
    #[error("get top block")]
    GetTopBlock,
    #[error("get top metadata")]
    GetTopMetadata,
    #[error("get topo height for hash")]
    GetTopoHeightForHash,
    #[error("get block hash for topoheight '{}'", _0)]
    GetBlockHashAtTopoHeight(TopoHeight),
    #[error("get transaction")]
    GetTransaction,
    #[error("get account registration topoheight")]
    AccountRegistrationTopoHeight,
    #[error("get asset")]
    Asset,
    #[error("get asset at topoheight {0}")]
    AssetAtTopoHeight(TopoHeight),
    #[error("get last balance")]
    LastBalance,
    #[error("get balance at topoheight {0}")]
    BalanceAtTopoHeight(TopoHeight),
    #[error("get last topoheight for balance")]
    LastTopoHeightForBalance,
    #[error("get block reward at topoheight {0}")]
    BlockRewardAtTopoHeight(TopoHeight),
    #[error("get supply at topoheight {0}")]
    SupplyAtTopoHeight(TopoHeight),
    #[error("get burned supply at topoheight {0}")]
    BurnedSupplyAtTopoHeight(TopoHeight),
    #[error("get blocks at height {0}")]
    BlocksAtHeight(u64),
    #[error("get block executor for tx")]
    BlockExecutorForTx,
    #[error("get blocks for tx")]
    TxBlocks,
    #[error("get difficulty for block hash")]
    DifficultyForBlockHash,
    #[error("get cumulative difficulty for block hash")]
    CumulativeDifficultyForBlockHash,
    #[error("get block header by hash")]
    GetBlockHeaderByHash,
    #[error("get estimated covariance for block hash")]
    EstimatedCovarianceForBlockHash,
    #[error("get balances merkle hash at topoheight {0}")]
    BalancesMerkleHashAtTopoHeight(TopoHeight),
    #[error("get last topoheight for nonce")]
    LastTopoheightForNonce,
    #[error("get last nonce")]
    LastNonce,
    #[error("get nonce at topoheight {0}")]
    NonceAtTopoHeight(TopoHeight),
    // Extra
    #[error("get network")]
    Network,
    #[error("get tips")]
    Tips,
    #[error("get pruned topoheight")]
    PrunedTopoHeight,
    #[error("get assets count")]
    AssetsCount,
    #[error("get txs count")]
    TxsCount,
    #[error("get blocks count")]
    BlocksCount,
    #[error("get accounts count")]
    AccountsCount,
    #[error("get block execution order count")]
    BlocksExecutionOrderCount,
    #[error("get top topoheight")]
    TopTopoHeight,
    #[error("get top height")]
    TopHeight,
    // Default
    #[error("delete data")]
    DeleteData,
    #[error("load data")]
    LoadData,
    #[error("load optional data")]
    LoadOptionalData,
    #[error("search block position in order")]
    SearchBlockPositionInOrder,
    #[error("get contract topoheight")]
    ContractTopoHeight,
    #[error("get contract at topoheight {0}")]
    ContractAtTopoHeight(TopoHeight),
    #[error("contracts count")]
    ContractsCount,
    #[error("get contract data topoheight")]
    ContractDataTopoHeight,
    #[error("get contract data at topoheight {0}")]
    ContractDataAtTopoHeight(TopoHeight),
    #[error("get contract data")]
    ContractData,
    #[error("get contract outputs")]
    ContractOutputs,
    #[error("get contract balance")]
    ContractBalance,
    #[error("get asset supply")]
    AssetSupply,
    #[error("get asset supply at topoheight {0}")]
    AssetSupplyAtTopoHeight(TopoHeight),
    #[error("get asset supply topoheight")]
    AssetSupplyTopoHeight,

    // Variants used by versioned data deletions
    #[error("versioned contract")]
    VersionedContract,
    #[error("versioned contract data")]
    VersionedContractData,
    #[error("versioned nonce")]
    VersionedNonce,
    #[error("versioned multisig")]
    VersionedMultisig,
    #[error("versioned balance")]
    VersionedBalance,
}

#[derive(Error, Debug, EnumDiscriminants)]
pub enum BlockchainError {
    #[error("Invalid configuration provided")]
    InvalidConfig,
    #[error("Invalid data on disk: corrupted")]
    CorruptedData,
    #[error("No contract balance found")]
    NoContractBalance,
    #[error("Contract already exists")]
    ContractAlreadyExists,
    #[error("Contract not found: {}", _0)]
    ContractNotFound(Hash),
    #[error("Invalid tip order for block {}, expected {}, got {}", _0, _1, _2)]
    InvalidTipsOrder(Hash, Hash, Hash),
    #[error("commit point already started")]
    CommitPointAlreadyStarted,
    #[error("commit point not started")]
    CommitPointNotStarted,
    #[error("no multisig found")]
    NoMultisig,
    #[error("Versioned data not found in disk")]
    VersionedNotFound,
    #[error("Block is not ordered")]
    BlockNotOrdered,
    #[error("Invalid balances merkle hash for block {}, expected {}, got {}", _0, _1, _2)]
    InvalidBalancesMerkleHash(Hash, Hash, Hash),
    #[error("Invalid tips merkle hash for block {}, expected {}, got {}", _0, _1, _2)]
    InvalidTipsMerkleHash(Hash, Hash, Hash),
    #[error("Transaction size is {} while limit is {}", human_bytes(*_0 as f64), human_bytes(*_1 as f64))]
    TxTooBig(usize, usize),
    #[error("Timestamp {} is less than parent", _0)]
    TimestampIsLessThanParent(TimestampMillis),
    #[error("Timestamp {} is greater than current time {}", _1, _0)]
    TimestampIsInFuture(TimestampMillis, TimestampMillis), // left is expected, right is got
    #[error("Block height mismatch, expected {}, got {}.", _0, _1)]
    InvalidBlockHeight(u64, u64),
    #[error("Block height is zero which is not allowed")]
    BlockHeightZeroNotAllowed,
    #[error("Block height is in stable height which is not allowed")]
    InvalidBlockHeightStableHeight,
    #[error("Invalid difficulty")]
    InvalidDifficulty,
    #[error("Tx nonce {} already used by Tx {}", _0, _1)]
    TxNonceAlreadyUsed(Nonce, Hash),
    #[error("Invalid hash, expected {}, got {}", _0, _1)]
    InvalidHash(Hash, Hash),
    #[error("Invalid previous block hash, expected {}, got {}", _0, _1)]
    InvalidPreviousBlockHash(Hash, Hash),
    #[error("Block size is more than limit, expected maximum: {}, got {}", _0, _1)]
    InvalidBlockSize(usize, usize),
    #[error("Block contains invalid txs count: expected {}, got {} txs.", _0, _1)]
    InvalidBlockTxs(usize, usize),
    #[error("Block contains an unknown tx: {}", _0)]
    InvalidTxInBlock(Hash),
    #[error("Tx {} not found in mempool", _0)]
    TxNotFound(Hash),
    #[error("Tx {} was present in mempool but not in sorted list!", _0)]
    TxNotFoundInSortedList(Hash),
    #[error("Tx {} already in mempool", _0)]
    TxAlreadyInMempool(Hash),
    #[error("Normal Tx {} is empty", _0)]
    TxEmpty(Hash),
    #[error("Transaction has an invalid reference: block hash not found")]
    InvalidReferenceHash,
    #[error("Transaction has an invalid reference: topoheight {0} is higher than our topoheight {1}")]
    InvalidReferenceTopoheight(u64, u64),
    #[error("No previous balance found")]
    NoPreviousBalanceFound,
    #[error("Transaction has an invalid reference: no balance version found in stable chain")]
    NoStableReferenceFound,
    #[error("Tx {} is already in block", _0)]
    TxAlreadyInBlock(Hash),
    #[error("Invalid Tx fee, expected at least {}, got {}", format_xelis(*_0), format_xelis(*_1))]
    InvalidTxFee(u64, u64),
    #[error("Fees are lower for this TX than the overrided TX, expected at least {}, got {}", format_xelis(*_0), format_xelis(*_1))]
    FeesToLowToOverride(u64, u64),
    #[error("No account found for {}", _0)]
    AccountNotFound(Address),
    #[error("Invalid transaction nonce: {}, account nonce is: {}", _0, _1)]
    InvalidTransactionNonce(Nonce, Nonce),
    #[error("Invalid transaction, sender trying to send coins to himself: {}", _0)]
    InvalidTransactionToSender(Hash),
    #[error("Invalid extra data in this transaction")]
    InvalidTransactionExtraData,
    #[error("Invalid extra data in transfer")]
    InvalidTransferExtraData,
    #[error("Invalid network state")]
    InvalidNetwork,
    #[error("Error while retrieving block by hash: {} not found", _0)]
    BlockNotFound(Hash),
    #[error("Error while retrieving block by height: {} not found", _0)]
    BlockHeightNotFound(u64),
    #[error("Chain has a too low cumulative difficulty")]
    LowerCumulativeDifficulty,
    #[error("No cumulative difficulty found")]
    NoCumulativeDifficulty,
    #[error(transparent)]
    ErrorStd(#[from] std::io::Error),
    #[error(transparent)]
    ErrorOnBech32(#[from] Bech32Error),
    #[error(transparent)]
    ErrorOnP2p(#[from] P2pError),
    #[error(transparent)]
    ErrorOnReader(#[from] ReaderError),
    #[error(transparent)]
    ErrorOnPrompt(#[from] PromptError),
    #[error(transparent)]
    ErrorOnSignature(#[from] ed25519_dalek::SignatureError),
    #[error("Poison Error: {}", _0)]
    PoisonError(String),
    #[error("Blockchain is syncing")]
    IsSyncing,
    #[error("Invalid transaction signature")]
    InvalidTransactionSignature,
    #[error("Genesis block is not mined by dev address!")]
    GenesisBlockMiner,
    #[error("Invalid genesis block")]
    InvalidGenesisBlock,
    #[error("Not enough blocks")]
    NotEnoughBlocks,
    #[error("Unknown data store error")]
    Unknown,
    #[error("No signature found for this TX")]
    NoTxSignature,
    #[error("Smart Contract not supported yet")]
    SmartContractTodo,
    #[error("Unexpected transaction variant to set fees")]
    UnexpectedTransactionVariant,
    #[error("Unexpected error on database: {}", _0)]
    DatabaseError(#[from] sled::Error),
    #[error("Unsupported operation")]
    UnsupportedOperation,
    #[error("Data not found on disk: {}", _0)]
    NotFoundOnDisk(DiskContext),
    #[error("Invalid config sync mode")]
    ConfigSyncMode,
    #[error("Expected at least one tips")]
    ExpectedTips,
    #[error("Block {0} has invalid tips count: {1}")]
    InvalidTipsCount(Hash, usize),
    #[error("Block {0} has an invalid tip {1} which is not present in chain")]
    InvalidTipsNotFound(Hash, Hash),
    #[error("Block {0} has invalid tips difficulty: {1}")]
    InvalidTipsDifficulty(Hash, Hash),
    #[error("Invalid block version")]
    InvalidBlockVersion,
    #[error("Invalid tx version")]
    InvalidTxVersion,
    #[error("Block is already in chain")]
    AlreadyInChain,
    #[error("Block has an invalid reachability")]
    InvalidReachability,
    #[error("Block has too much deviated")]
    BlockDeviation,
    #[error("Invalid genesis block hash")]
    InvalidGenesisHash,
    #[error("Invalid tx {} nonce (got {} expected {}) for {}", _0, _1, _2, _3)]
    InvalidTxNonce(Hash, Nonce, Nonce, Address),
    #[error("Invalid tx nonce {} for mempool cache, range: [{}-{}]", _0, _1, _2)]
    InvalidTxNonceMempoolCache(Nonce, Nonce, Nonce),
    #[error("Invalid asset ID: {}", _0)]
    AssetNotFound(Hash),
    #[error(transparent)]
    DifficultyError(#[from] DifficultyError),
    #[error("No balance found on disk for {}", _0)]
    NoBalance(Address),
    #[error("No balance changes for {} at topoheight {} and asset {}", _0, _1, _2)]
    NoBalanceChanges(Address, TopoHeight, Hash),
    #[error("No nonce found on disk for {}", _0)]
    NoNonce(Address),
    #[error("Overflow detected")]
    Overflow,
    #[error("Error, block {} include a dead tx {} from stable height {} executed in block {}", _0, _1, _2, _3)]
    DeadTxFromStableHeight(Hash, Hash, u64, Hash),
    #[error("Error, block {} include a dead tx from tips {}", _0, _1)]
    DeadTxFromTips(Hash, Hash),
    #[error("TX {} is already in blockchain", _0)]
    TxAlreadyInBlockchain(Hash),
    #[error("Cannot prune, not enough blocks")]  
    PruneHeightTooHigh,
    #[error("Cannot prune until topoheight 0, provide a positive number")]
    PruneZero,
    #[error("Prune topoheight is lower or equal than previous pruned topoheight")]
    PruneLowerThanLastPruned,
    #[error("Auto prune mode is misconfigured")]
    AutoPruneMode,
    #[error(transparent)]
    TryFromSliceError(#[from] std::array::TryFromSliceError),
    #[error("Invalid ciphertext")]
    InvalidCiphertext,
    #[error("Invalid chain state, no sender output ?")]
    NoSenderOutput,
    #[error("Invalid chain state, sender {} account is not found", _0)]
    NoTxSender(Address),
    #[error(transparent)]
    DecompressionError(#[from] DecompressionError),
    #[error(transparent)]
    Any(#[from] anyhow::Error),
    #[error("Invalid nonce: expected {}, got {}", _0, _1)]
    InvalidNonce(Nonce, Nonce),
    #[error("Sender cannot be receiver")]
    SenderIsReceiver,
    #[error("Invalid transaction proof: {}", _0)]
    TransactionProof(ProofVerificationError),
    #[error("Error while generating pow hash")]
    POWHashError(#[from] XelisHashError),
    #[error("Transfer count is invalid")]
    TransferCount,
    #[error("Invalid commitments assets")]
    Commitments,
    #[error("MultiSig is not configured")]
    MultiSigNotConfigured,
    #[error("Invalid multisig participants count")]
    MultiSigParticipants,
    #[error("Invalid multisig threshold")]
    MultiSigThreshold,
    #[error("Invalid transaction format")]
    InvalidTransactionFormat,
    #[error("Invalid invoke contract")]
    InvalidInvokeContract,
    #[error("Deposit not found")]
    DepositNotFound,
    #[error("MultiSig not found")]
    MultiSigNotFound,
    #[error("Error in module: {}", _0)]
    ModuleError(String),
    #[error("Invalid transaction in block while verifying in multi-thread mode")]
    InvalidTransactionMultiThread,
}

impl BlockchainError {
    pub fn id(&self) -> usize {
        self.discriminant() as usize
    }
}

impl From<BlockchainError> for InternalRpcError {
    fn from(value: BlockchainError) -> Self {
        let id = value.id() as i16;
        InternalRpcError::CustomAny(200 + id, value.into())
    }
}

impl<T> From<PoisonError<T>> for BlockchainError {
    fn from(err: PoisonError<T>) -> Self {
        Self::PoisonError(format!("{}", err))
    }
}

impl From<VerificationError<BlockchainError>> for BlockchainError {
    fn from(value: VerificationError<BlockchainError>) -> Self {
        match value {
            VerificationError::InvalidNonce(expected, got) => BlockchainError::InvalidNonce(expected, got),
            VerificationError::SenderIsReceiver => BlockchainError::NoSenderOutput,
            VerificationError::InvalidSignature => BlockchainError::InvalidTransactionSignature,
            VerificationError::State(s) => s,
            VerificationError::Proof(proof) => BlockchainError::TransactionProof(proof),
            VerificationError::TransferCount => BlockchainError::TransferCount,
            VerificationError::Commitments => BlockchainError::Commitments,
            VerificationError::TransactionExtraDataSize => BlockchainError::InvalidTransactionExtraData,
            VerificationError::TransferExtraDataSize => BlockchainError::InvalidTransferExtraData,
            VerificationError::MultiSigNotConfigured => BlockchainError::MultiSigNotConfigured,
            VerificationError::MultiSigParticipants => BlockchainError::MultiSigParticipants,
            VerificationError::MultiSigThreshold => BlockchainError::MultiSigThreshold,
            VerificationError::InvalidFormat => BlockchainError::InvalidTransactionFormat,
            VerificationError::MultiSigNotFound => BlockchainError::MultiSigNotFound,
            VerificationError::ModuleError(e) => BlockchainError::ModuleError(e),
            VerificationError::AnyError(e) => BlockchainError::Any(e),
            VerificationError::GasOverflow => BlockchainError::Overflow,
            VerificationError::InvalidInvokeContract => BlockchainError::InvalidInvokeContract,
            VerificationError::DepositNotFound => BlockchainError::DepositNotFound,
            e => BlockchainError::Any(e.into())
        }
    }
}