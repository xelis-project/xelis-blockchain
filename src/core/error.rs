use crate::p2p::error::P2pError;
use crate::crypto::hash::Hash;
use crate::crypto::key::PublicKey;
use crate::crypto::bech32::Bech32Error;
use super::reader::ReaderError;
use super::prompt::prompt::PromptError;
use std::sync::PoisonError;
use thiserror::Error;



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
    #[error("Invalid difficulty")]
    InvalidDifficulty,
    #[error("Invalid hash, expected {}, got {}", _0, _1)]
    InvalidHash(Hash, Hash),
    #[error("Invalid previous block hash, expected {}, got {}", _0, _1)]
    InvalidPreviousBlockHash(Hash, Hash),
    #[error("Block size is more than limit: {}, got {}", _0, _1)]
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
    #[error("Address {} should have at least {}", _0, _1)]
    NotEnoughFunds(PublicKey, u64),
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
    #[error("Difficulty cannot be zero!")]
    DifficultyCannotBeZero,
    #[error("Difficulty error on conversion to BigUint")]
    DifficultyErrorOnConversion,
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
    InvalidTxNonce
}

impl<T> From<PoisonError<T>> for BlockchainError {
    fn from(err: PoisonError<T>) -> Self {
        Self::PoisonError(format!("{}", err))
    }
}