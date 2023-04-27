use crate::p2p::error::P2pError;
use std::sync::PoisonError;
use thiserror::Error;
use xelis_common::{crypto::{hash::Hash, key::PublicKey, bech32::Bech32Error}, serializer::ReaderError, prompt::PromptError, difficulty::DifficultyError};

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
    #[error("Timestamp {} is less than parent", _0)]
    TimestampIsLessThanParent(u128),
    #[error("Timestamp {} is greater than current time {}", _0, _1)]
    TimestampIsInFuture(u128, u128), // left is expected, right is got
    #[error("Block height mismatch, expected {}, got {}.", _0, _1)]
    InvalidBlockHeight(u64, u64),
    #[error("Block height is in stable height which is not allowed")]
    InvalidBlockHeightStableHeight,
    #[error("Invalid difficulty")]
    InvalidDifficulty,
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
    #[error("Tx {} has too many output", _0)]
    TooManyOutputInTx(Hash),
    #[error("Tx {} is already in block", _0)]
    TxAlreadyInBlock(Hash),
    #[error("Duplicate registration tx for address '{}' found in same block", _0)]
    DuplicateRegistration(PublicKey), // address
    #[error("Invalid Tx fee, expected at least {}, got {}", _0, _1)]
    InvalidTxFee(u64, u64),
    #[error("Address {} is not registered", _0)]
    AddressNotRegistered(PublicKey),
    #[error("Address {} is already registered", _0)]
    AddressAlreadyRegistered(PublicKey),
    #[error("Address {} should have {} for {} but have {}", _0, _2, _1, _3)]
    NotEnoughFunds(PublicKey, Hash, u64, u64), // address, asset, balance, expected
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
    #[error("Data not found on disk: {}", _0)]
    NotFoundOnDisk(DiskContext),
    #[error("Expected at least one tips")]
    ExpectedTips,
    #[error("Block has invalid tips")]
    InvalidTips,
    #[error("Block is already in chain")]
    AlreadyInChain,
    #[error("Block has an invalid reachability")]
    InvalidReachability,
    #[error("Block has too much deviated")]
    BlockDeviation,
    #[error("Invalid genesis block hash")]
    InvalidGenesisHash,
    #[error("Invalid tx nonce for account")]
    InvalidTxNonce,
    #[error("Invalid asset ID: {}", _0)]
    AssetNotFound(Hash),
    #[error(transparent)]
    DifficultyError(#[from] DifficultyError),
    #[error("No balance found on disk")]
    NoBalance,
    #[error("No balance changes for specific topoheight and asset")]
    NoBalanceChanges,
    #[error("Overflow detected")]
    Overflow,
    #[error("Error, block include a dead tx {}", _0)]
    DeadTx(Hash),
    #[error("A non-zero value is required for burn")]
    NoValueForBurn,
    #[error("TX {} is already in blockchain", _0)]
    TxAlreadyInBlockchain(Hash)
}

impl<T> From<PoisonError<T>> for BlockchainError {
    fn from(err: PoisonError<T>) -> Self {
        Self::PoisonError(format!("{}", err))
    }
}