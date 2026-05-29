use strum::{EnumDiscriminants, IntoDiscriminant, IntoStaticStr};
use thiserror::Error;
use chacha20poly1305::Error as CryptoError;
use xelis_common::{
    crypto::{Hash, elgamal::DecompressionError, proofs::ProofGenerationError},
    error::ErrorWithKind,
    transaction::{builder::{GenerationError, GenerationStateError},
    extra_data::CipherFormatError},
    utils::{format_coin, format_xelis}
};

#[cfg(feature = "xswd")]
use xelis_common::rpc::{RPCError, InternalRpcError};

#[cfg(feature = "network_handler")]
use super::network_handler::NetworkError;

#[derive(Error, Debug, EnumDiscriminants, IntoStaticStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum WalletError {
    #[error("Cipher error")]
    Cipher,
    #[error("Asset {0} is not tracked by wallet")]
    AssetNotTracked(Hash),
    #[error("Invalid datetime")]
    InvalidDatetime,
    #[error("Invalid builder state, tx hash not built")]
    TxNotBuilt,
    #[error("Transaction too big: {} bytes, max is {} bytes", _0, _1)]
    TransactionTooBig(usize, usize),
    #[error("Invalid key pair")]
    InvalidKeyPair,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Expected a TX")]
    ExpectedOneTx,
    #[error("Too many txs included max is {}", u8::MAX)]
    TooManyTx,
    #[error("Transaction owner is the receiver")]
    TxOwnerIsReceiver,
    #[error("Error from crypto: {}", _0)]
    CryptoError(CryptoError),
    #[error("Unexpected error on database: {}", _0)]
    DatabaseError(#[from] sled::Error),
    #[error("Invalid encrypted value: minimum 25 bytes")]
    InvalidEncryptedValue,
    #[error("No salt found in storage")]
    NoSalt,
    #[error("Error while hashing: {}", _0)]
    AlgorithmHashingError(String),
    #[error("Error while fetching encrypted master key: not found in DB")]
    NoMasterKeyFound,
    #[error("Error while fetching password salt: not found in DB")]
    NoPasswordSaltFound,
    #[error("Invalid salt size stored in storage, expected 32 bytes")]
    InvalidSaltSize,
    #[error("Error while fetching password salt from DB")]
    NoSaltFound,
    #[error("Your wallet contains only {} instead of {} for asset {}", format_coin(*_0, *_2), format_coin(*_1, *_2), _3)]
    NotEnoughFunds(u64, u64, u8, Hash),
    #[error("Your wallet don't have enough funds to pay fees: expected {} but have only {}", format_xelis(*_0), format_xelis(*_1))]
    NotEnoughFundsForFee(u64, u64),
    #[error("Invalid address params")]
    InvalidAddressParams,
    #[error("Invalid extra data in this transaction, expected maximum {} bytes but got {} bytes", _0, _1)]
    ExtraDataTooBig(usize, usize),
    #[error("Wallet is not in online mode")]
    NotOnlineMode,
    #[error("Wallet is already in online mode")]
    AlreadyOnlineMode,
    #[error("Asset is already present on disk")]
    AssetAlreadyRegistered,
    #[error("Topoheight is too high to rescan")]
    RescanTopoheightTooHigh,
    #[error(transparent)]
    Any(#[from] ErrorWithKind),
    #[error("No API Server is running")]
    NoAPIServer,
    #[error("RPC Server is not running")]
    RPCServerNotRunning,
    #[error("RPC Server is already running")]
    RPCServerAlreadyRunning,
    #[error("Invalid fees provided, minimum fees calculated: {}, provided: {}", format_xelis(*_0), format_xelis(*_1))]
    InvalidFeeProvided(u64, u64),
    #[error("Wallet name cannot be empty")]
    EmptyName,
    #[error("No handler available for this request")]
    NoHandlerAvailable,
    #[cfg(feature = "network_handler")]
    #[error(transparent)]
    NetworkError(#[from] NetworkError),
    #[error("Balance for asset {} was not found", _0)]
    BalanceNotFound(Hash),
    #[error("No result found for ciphertext")]
    CiphertextDecode,
    #[error(transparent)]
    AEADCipherFormatError(#[from] CipherFormatError),
    #[error("No network handler available")]
    NoNetworkHandler,
    #[error("Nonce generation")]
    NonceGeneration,
    #[error("Poison error")]
    PoisonError,
    #[error("unsupported operation")]
    Unsupported,
    #[error(transparent)]
    GenerationError(#[from] GenerationError),
    #[error(transparent)]
    ProofGenerationError(#[from] ProofGenerationError),
    #[error(transparent)]
    DecompressionError(#[from] DecompressionError),
}

impl From<GenerationStateError<Self>> for WalletError {
    fn from(value: GenerationStateError<Self>) -> Self {
        match value {
            GenerationStateError::State(e) => e,
            GenerationStateError::GenerationError(e) => Self::GenerationError(e),
        }
    }
}

impl From<anyhow::Error> for WalletError {
    fn from(value: anyhow::Error) -> Self {
        Self::Any(ErrorWithKind::from(value))
    }
}

impl WalletError {
    // Return the id for the variant
    pub  fn id(&self) -> usize {
        self.discriminant() as usize
    }

    // Return the kind for the variant, used for RPC error mapping
    pub fn kind(&self) -> &'static str {
        match self {
            WalletError::Any(e) => e.kind,
            WalletError::GenerationError(e) => e.into(),
            _ => self.into()
        }
    }
}

#[cfg(feature = "xswd")]
impl RPCError for WalletError {
    fn kind(&self) -> &'static str {
        WalletError::kind(self)
    }
}

#[cfg(feature = "xswd")]
impl From<WalletError> for InternalRpcError {
    fn from(e: WalletError) -> Self {
        InternalRpcError::Any {
            kind: e.kind(),
            error: e.into()
        }
    }
}