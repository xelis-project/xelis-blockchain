use anyhow::Error as AnyError;
use thiserror::Error;
use xelis_vm::ValidatorError;

use crate::{
    account::Nonce,
    crypto::{
        proofs::ProofVerificationError,    
        Hash
    },
    contract::vm::ContractError
};

#[derive(Error, Debug)]
pub enum VerificationError<T> {
    #[error("State error: {0}")]
    State(T),
    #[error("Invalid TX {} nonce, got {} expected {}", _0, _1, _2)]
    InvalidNonce(Hash, Nonce, Nonce),
    #[error("Sender is receiver")]
    SenderIsReceiver,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Proof verification error: {0}")]
    Proof(#[from] ProofVerificationError),
    #[error("Extra Data is too big in transfer")]
    TransferExtraDataSize,
    #[error("Extra Data is too big in transaction")]
    TransactionExtraDataSize,
    #[error("Transfer count is invalid")]
    TransferCount,
    #[error("Deposit count is invalid")]
    DepositCount,
    #[error("Invalid commitments assets")]
    Commitments,
    #[error("Invalid multisig participants count")]
    MultiSigParticipants,
    #[error("Invalid multisig threshold")]
    MultiSigThreshold,
    #[error("MultiSig not configured")]
    MultiSigNotConfigured,
    #[error("MultiSig not found")]
    MultiSigNotFound,
    #[error("Invalid format")]
    InvalidFormat,
    #[error("Module error: {0}")]
    ModuleError(#[from] ValidatorError),
    #[error(transparent)]
    AnyError(#[from] AnyError),
    #[error("Invalid invoke contract")]
    InvalidInvokeContract,
    #[error("Contract not found")]
    ContractNotFound,
    #[error("Deposit decompressed not found")]
    DepositNotFound,
    #[error("Configured max gas is above the network limit")]
    MaxGasReached,
    #[error(transparent)]
    Contract(#[from] ContractError<T>),
}