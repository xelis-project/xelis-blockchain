use crate::p2p::error::P2pError;
use std::sync::PoisonError;
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
    difficulty::DifficultyError,
    prompt::PromptError,
    serializer::ReaderError,
    time::TimestampMillis,
    transaction::verify::VerificationError
};
use human_bytes::human_bytes;

#[derive(Error, Debug)]
pub enum DiskContext {
    #[error("get top block")]
    GetTopBlock,
    #[error("get top metadata")]
    GetTopMetadata,
    #[error("get topo height for hash '{}'", _0)]
    GetTopoHeight(Hash),
    #[error("get block hash for height '{}'", _0)]
    GetBlockHash(u64),
    #[error("delete data")]
    DeleteData,
    #[error("load data")]
    LoadData,
}

#[derive(Error, Debug)]
pub enum BlockchainError {
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
    #[error("Timestamp {} is greater than current time {}", _0, _1)]
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
    TxNonceAlreadyUsed(u64, Hash),
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
    #[error("Transaction has an invalid reference: topoheight is too high")]
    InvalidReferenceTopoheight,
    #[error("Tx {} has too many output", _0)]
    TooManyOutputInTx(Hash),
    #[error("Tx {} is already in block", _0)]
    TxAlreadyInBlock(Hash),
    #[error("Duplicate registration tx for address '{}' found in same block", _0)]
    DuplicateRegistration(Address), // address
    #[error("Invalid Tx fee, expected at least {}, got {}", _0, _1)]
    InvalidTxFee(u64, u64),
    #[error("Fees are lower for this TX than the overrided TX, expected at least {}, got {}", _0, _1)]
    FeesToLowToOverride(u64, u64),
    #[error("No account found for {}", _0)]
    AccountNotFound(Address),
    #[error("Address {} is not registered", _0)]
    AddressNotRegistered(Address),
    #[error("Address {} is already registered", _0)]
    AddressAlreadyRegistered(Address),
    #[error("Address {} should have {} for {} but have {}", _0, _2, _1, _3)]
    NotEnoughFunds(Address, Hash, u64, u64), // address, asset, balance, expected
    #[error("Coinbase Tx not allowed: {}", _0)]
    CoinbaseTxNotAllowed(Hash),
    #[error("Invalid block reward, expected {}, got {}", _0, _1)]
    InvalidBlockReward(u64, u64),
    #[error("Invalid fee reward for this block, expected {}, got {}", _0, _1)]
    InvalidFeeReward(u64, u64),
    #[error("Invalid circulating supply, expected {}, got {} coins generated!", _0, _1)]
    InvalidCirculatingSupply(u64, u64),
    #[error("Invalid tx registration PoW: {}", _0)]
    InvalidTxRegistrationPoW(Hash),
    #[error("Invalid tx registration, tx has a signature: {}", _0)]
    InvalidTxRegistrationSignature(Hash),
    #[error("Invalid transaction nonce: {}, account nonce is: {}", _0, _1)]
    InvalidTransactionNonce(u64, u64),
    #[error("Invalid transaction, sender trying to send coins to himself: {}", _0)]
    InvalidTransactionToSender(Hash),
    #[error("Invalid extra data in this transaction, expected maximum {} bytes but got {} bytes", _0, _1)]
    InvalidTransactionExtraDataTooBig(usize, usize),
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
    #[error("Found a signature on the transaction, but its not required")]
    UnexpectedTransactionSignature,
    #[error("Invalid miner transaction in the block, only coinbase tx is allowed")]
    InvalidMinerTx,
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
    #[error("Invalid paramater: max chain response size isn't in range")]
    ConfigMaxChainResponseSize,
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
    InvalidTxNonce(Hash, u64, u64, Address),
    #[error("Invalid tx nonce {} for mempool cache, range: [{}-{}]", _0, _1, _2)]
    InvalidTxNonceMempoolCache(u64, u64, u64),
    #[error("Invalid asset ID: {}", _0)]
    AssetNotFound(Hash),
    #[error(transparent)]
    DifficultyError(#[from] DifficultyError),
    #[error("No balance found on disk for {}", _0)]
    NoBalance(Address),
    #[error("No balance changes for {} at topoheight {} and asset {}", _0, _1, _2)]
    NoBalanceChanges(Address, u64, Hash),
    #[error("No nonce found on disk for {}", _0)]
    NoNonce(Address),
    #[error("No nonce changes for {} at specific topoheight", _0)]
    NoNonceChanges(Address),
    #[error("Overflow detected")]
    Overflow,
    #[error("Error, block include a dead tx {}", _0)]
    DeadTx(Hash),
    #[error("A non-zero value is required for burn")]
    NoValueForBurn,
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
    #[error("Invalid nonce")]
    InvalidNonce,
    #[error("Sender cannot be receiver")]
    SenderIsReceiver,
    #[error("Invalid transaction proof: {}", _0)]
    TransactionProof(ProofVerificationError),
    #[error("Error while generating pow hash")]
    POWHashError(#[from] XelisHashError),
}

impl<T> From<PoisonError<T>> for BlockchainError {
    fn from(err: PoisonError<T>) -> Self {
        Self::PoisonError(format!("{}", err))
    }
}

impl From<VerificationError<BlockchainError>> for BlockchainError {
    fn from(value: VerificationError<BlockchainError>) -> Self {
        match value {
            VerificationError::InvalidNonce => BlockchainError::InvalidNonce,
            VerificationError::SenderIsReceiver => BlockchainError::NoSenderOutput,
            VerificationError::InvalidSignature => BlockchainError::InvalidTransactionSignature,
            VerificationError::State(s) => s,
            VerificationError::Proof(proof) => BlockchainError::TransactionProof(proof)
        }
    }
}