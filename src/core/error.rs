use crate::p2p::error::P2pError;
use crate::crypto::hash::Hash;
use crate::crypto::key::PublicKey;
use crate::crypto::bech32::Bech32Error;

pub enum BlockchainError {
    TimestampIsLessThanParent(u64),
    TimestampIsInFuture(u64, u64), //left is expected, right is got
    InvalidBlockHeight(u64, u64),
    InvalidDifficulty(u64, u64),
    InvalidHash(Hash, Hash),
    InvalidPreviousBlockHash(Hash, Hash),
    InvalidBlockSize(usize, usize),
    InvalidBlockTxs(usize, usize),
    InvalidTxInBlock(Hash),
    TxNotFound(Hash),
    TxAlreadyInMempool(Hash),
    TxEmpty(Hash),
    TxAlreadyInBlock(Hash),
    DuplicateRegistration(PublicKey), //address
    InvalidTxFee(u64, u64),
    AddressNotRegistered(PublicKey),
    AddressAlreadyRegistered(PublicKey),
    NotEnoughFunds(PublicKey, u64),
    CoinbaseTxNotAllowed(Hash),
    InvalidBlockReward(u64, u64),
    InvalidFeeReward(u64, u64),
    InvalidCirculatingSupply(u64, u64),
    InvalidTxRegistrationPoW(Hash),
    InvalidTxRegistrationSignature(Hash),
    InvalidTransactionNonce(u64, u64),
    InvalidTransactionToSender(Hash),
    ErrorOnBech32(Bech32Error),
    BlockNotFound(Hash),
    ErrorOnP2p(P2pError),
    InvalidTransactionSignature,
    DifficultyCannotBeZero,
    DifficultyErrorOnConversion,
    InvalidMinerTx,
}

use std::fmt::{Display, Error, Formatter};

impl Display for BlockchainError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        use BlockchainError::*;
        match self {
            AddressAlreadyRegistered(address) => write!(f, "Address {} is already registered", address.to_address().unwrap()),
            AddressNotRegistered(address) => write!(f, "Address {} is not registered", address.to_address().unwrap()),
            InvalidBlockHeight(expected, got) => write!(f, "Block height mismatch, expected {}, got {}", expected, got),
            InvalidBlockSize(expected, got) => write!(f, "Block size is more than limit: {}, got {}", expected, got),
            InvalidBlockTxs(expected, got) => write!(f, "Block contains invalid txs count: expected {}, got {} txs.", expected, got),
            InvalidTxInBlock(hash) => write!(f, "Block contains an unknown tx: {}", hash),
            InvalidDifficulty(expected, got) => write!(f, "Invalid difficulty, expected {}, got {}", expected, got),
            InvalidHash(expected, got) => write!(f, "Invalid hash, expected {}, got {}", expected, got),
            InvalidPreviousBlockHash(expected, got) => write!(f, "Invalid previous block hash, expected {}, got {}", expected, got),
            InvalidTxFee(expected, got) => write!(f, "Invalid Tx fee, expected at least {}, got {}", expected, got),
            TimestampIsInFuture(timestamp, current) => write!(f, "Timestamp {} is greater than current time {}", timestamp, current),
            TimestampIsLessThanParent(timestamp) => write!(f, "Timestamp {} is less than parent", timestamp),
            TxNotFound(hash) => write!(f, "Tx {} not found in mempool", hash),
            TxAlreadyInMempool(hash) => write!(f, "Tx {} already in mempool", hash),
            TxEmpty(hash) => write!(f, "Normal Tx {} is empty", hash),
            TxAlreadyInBlock(hash) => write!(f, "Tx {} is already in block", hash),
            DuplicateRegistration(address) => write!(f, "Duplicate registration tx for address '{}' found in same block", address.to_address().unwrap()),
            NotEnoughFunds(address, amount) => write!(f, "Address {} should have at least {}", address.to_address().unwrap(), amount),
            CoinbaseTxNotAllowed(hash) => write!(f, "Coinbase Tx not allowed: {}", hash),
            InvalidBlockReward(expected, got) => write!(f, "Invalid block reward, expected {}, got {}", expected, got),
            InvalidFeeReward(expected, got) => write!(f, "Invalid fee reward for this block, expected {}, got {}", expected, got),
            InvalidCirculatingSupply(expected, got) => write!(f, "Invalid circulating supply, expected {}, got {} coins generated!", expected, got),
            InvalidTxRegistrationPoW(hash) => write!(f, "Invalid tx registration PoW: {}", hash),
            InvalidTxRegistrationSignature(hash) => write!(f, "Invalid tx registration, tx has a signature: {}", hash),
            InvalidTransactionNonce(expected, got) => write!(f, "Invalid transaction nonce: {}, account nonce is: {}", got, expected),
            InvalidTransactionToSender(hash) => write!(f, "Invalid transaction, sender trying to send coins to himself: {}", hash),
            ErrorOnBech32(e) => write!(f, "Error occured on bech32: {}", e),
            BlockNotFound(hash) => write!(f, "Error while retrieving block by hash: {} not found", hash),
            ErrorOnP2p(p2p) => write!(f, "Error on p2p: {}", p2p),
            InvalidTransactionSignature => write!(f, "Invalid transaction signature"),
            DifficultyCannotBeZero => write!(f, "Difficulty cannot be zero!"),
            DifficultyErrorOnConversion => write!(f, "Difficulty error on conversion to BigUint"),
            InvalidMinerTx => write!(f, "Invalid miner transaction in the block, only coinbase tx is allowed")
        }
    }
}