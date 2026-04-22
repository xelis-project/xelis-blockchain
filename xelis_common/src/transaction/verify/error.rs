use anyhow::Error as AnyError;
use strum::IntoStaticStr;
use thiserror::Error;
use xelis_vm::ValidatorError;

use crate::{
    account::Nonce,
    crypto::{
        proofs::ProofVerificationError,    
        Hash
    },
    contract::vm::{ContractError, ContractStateError},
};

#[derive(Error, Debug)]
pub enum VerificationStateError<T> {
    #[error("State error: {0}")]
    State(T),
    #[error(transparent)]
    VerificationError(VerificationError),
    #[error(transparent)]
    ContractError(#[from] ContractError),
}

impl<S, T: Into<VerificationError>> From<T> for VerificationStateError<S> {
    fn from(err: T) -> Self {
        Self::VerificationError(err.into())
    }
}

impl<S> From<ContractStateError<S>> for VerificationStateError<S> {
    fn from(err: ContractStateError<S>) -> Self {
        match err {
            ContractStateError::State(state_err) => Self::State(state_err),
            ContractStateError::Contract(contract_err) => Self::ContractError(contract_err),
        }
    }
}

#[derive(Error, Debug, IntoStaticStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationError {
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
    #[error("Transaction size {} bytes is above the maximum allowed {} bytes", _0, _1)]
    TxTooBig(usize, usize),
}