mod data;
pub mod wallet;
pub mod daemon;
pub mod query;

use std::borrow::Cow;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use bulletproofs::RangeProof;
use crate::{
    account::Nonce,
    contract::{ContractLog, ScheduledExecutionKind},
    crypto::{
        elgamal::{CompressedCommitment, CompressedHandle},
        proofs::CiphertextValidityProof,
        Address,
        Hash,
        Signature
    },
    transaction::{
        extra_data::UnknownExtraDataFormat,
        multisig::MultiSig,
        BurnPayload,
        InvokeContractPayload,
        DeployContractPayload,
        MultiSigPayload,
        Reference,
        SourceCommitment,
        Transaction,
        TransactionType,
        TransferPayload,
        TxVersion,
    }
};
pub use data::*;

#[derive(Serialize, Deserialize)]
pub struct SubscribeParams<'a, E: Clone> {
    pub notify: Cow<'a, E>
}

#[derive(Serialize, Deserialize)]
pub struct EventResult<'a, E: Clone> {
    pub event: Cow<'a, E>,
    #[serde(flatten)]
    pub value: Value
}

#[derive(Serialize, Deserialize)]
pub struct DataHash<'a, T: Clone> {
    pub hash: Cow<'a, Hash>,
    #[serde(flatten)]
    pub data: Cow<'a, T>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RPCTransferPayload<'a> {
    pub asset: Cow<'a, Hash>,
    pub destination: Address,
    pub extra_data: Cow<'a, Option<UnknownExtraDataFormat>>,
    pub commitment: Cow<'a, CompressedCommitment>,
    pub sender_handle: Cow<'a, CompressedHandle>,
    pub receiver_handle: Cow<'a, CompressedHandle>,
    pub ct_validity_proof: Cow<'a, CiphertextValidityProof>,
}

impl<'a> From<RPCTransferPayload<'a>> for TransferPayload {
    fn from(transfer: RPCTransferPayload<'a>) -> Self {
        TransferPayload::new(
            transfer.asset.into_owned(),
            transfer.destination.to_public_key(),
            transfer.extra_data.into_owned(),
            transfer.commitment.into_owned(),
            transfer.sender_handle.into_owned(),
            transfer.receiver_handle.into_owned(),
            transfer.ct_validity_proof.into_owned()
        )
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum RPCTransactionType<'a> {
    Transfers(Vec<RPCTransferPayload<'a>>),
    Burn(Cow<'a, BurnPayload>),
    MultiSig(Cow<'a, MultiSigPayload>),
    InvokeContract(Cow<'a, InvokeContractPayload>),
    DeployContract(Cow<'a, DeployContractPayload>)
}

impl<'a> RPCTransactionType<'a> {
    pub fn from_type(data: &'a TransactionType, mainnet: bool) -> Self {
        match data {
            TransactionType::Transfers(transfers) => {
                let mut rpc_transfers = Vec::new();
                for transfer in transfers {
                    rpc_transfers.push(RPCTransferPayload {
                        asset: Cow::Borrowed(transfer.get_asset()),
                        destination: transfer.get_destination().as_address(mainnet),
                        extra_data: Cow::Borrowed(transfer.get_extra_data()),
                        commitment: Cow::Borrowed(transfer.get_commitment()),
                        sender_handle: Cow::Borrowed(transfer.get_sender_handle()),
                        receiver_handle: Cow::Borrowed(transfer.get_receiver_handle()),
                        ct_validity_proof: Cow::Borrowed(transfer.get_proof()),
                    });
                }
                Self::Transfers(rpc_transfers)
            },
            TransactionType::Burn(burn) => Self::Burn(Cow::Borrowed(burn)),
            TransactionType::MultiSig(payload) => Self::MultiSig(Cow::Borrowed(payload)),
            TransactionType::InvokeContract(payload) => Self::InvokeContract(Cow::Borrowed(payload)),
            TransactionType::DeployContract(payload) => Self::DeployContract(Cow::Borrowed(payload))
        }
    }
}

impl From<RPCTransactionType<'_>> for TransactionType {
    fn from(data: RPCTransactionType) -> Self {
        match data {
            RPCTransactionType::Transfers(transfers) => {
                TransactionType::Transfers(transfers.into_iter().map(|transfer| transfer.into()).collect::<Vec<TransferPayload>>())
            },
            RPCTransactionType::Burn(burn) => TransactionType::Burn(burn.into_owned()),
            RPCTransactionType::MultiSig(payload) => TransactionType::MultiSig(payload.into_owned()),
            RPCTransactionType::InvokeContract(payload) => TransactionType::InvokeContract(payload.into_owned()),
            RPCTransactionType::DeployContract(payload) => TransactionType::DeployContract(payload.into_owned())
        }
    }
}

// This is exactly the same as the one in xelis_common/src/transaction/mod.rs
// We use this one for serde (de)serialization
// So we have addresses displayed as strings and not Public Key as bytes
// This is much more easier for developers relying on the API
#[derive(Serialize, Deserialize, Clone)]
pub struct RPCTransaction<'a> {
    pub hash: Cow<'a, Hash>,
    /// Version of the transaction
    pub version: TxVersion,
    // Source of the transaction
    pub source: Address,
    /// Type of the transaction
    pub data: RPCTransactionType<'a>,
    /// Fees in XELIS
    pub fee: u64,
    // Maximum fee allowed to be paid
    pub fee_limit: u64,
    /// nonce must be equal to the one on chain account
    /// used to prevent replay attacks and have ordered transactions
    pub nonce: Nonce,
    /// We have one source commitment and equality proof per asset used in the tx.
    pub source_commitments: Cow<'a, Vec<SourceCommitment>>,
    /// The range proof is aggregated across all transfers and across all assets.
    pub range_proof: Cow<'a, RangeProof>,
    /// Reference at which block the transaction was built
    pub reference: Cow<'a, Reference>,
    /// Multisig data if the transaction is a multisig transaction
    pub multisig: Cow<'a, Option<MultiSig>>,
    /// Signature of the transaction
    pub signature: Cow<'a, Signature>,
    /// TX size in bytes
    pub size: usize
}

impl<'a> RPCTransaction<'a> {
    pub fn from_tx(tx: &'a Transaction, hash: &'a Hash, size: usize, mainnet: bool) -> Self {
        Self {
            hash: Cow::Borrowed(hash),
            version: tx.get_version(),
            source: tx.get_source().as_address(mainnet),
            data: RPCTransactionType::from_type(tx.get_data(), mainnet),
            fee: tx.get_fee(),
            fee_limit: tx.get_fee_limit(),
            nonce: tx.get_nonce(),
            source_commitments: Cow::Borrowed(tx.get_source_commitments()),
            range_proof: Cow::Borrowed(tx.get_range_proof()),
            reference: Cow::Borrowed(tx.get_reference()),
            multisig: Cow::Borrowed(tx.get_multisig()),
            signature: Cow::Borrowed(tx.get_signature()),
            size
        }
    }
}

impl<'a> From<RPCTransaction<'a>> for Transaction {
    fn from(tx: RPCTransaction<'a>) -> Self {
        Transaction::new(
            tx.version,
            tx.source.to_public_key(),
            tx.data.into(),
            tx.fee,
            tx.fee_limit,
            tx.nonce,
            tx.source_commitments.into_owned(),
            tx.range_proof.into_owned(),
            tx.reference.into_owned(),
            tx.multisig.into_owned(),
            tx.signature.into_owned()
        )
    }
}

// We create a type above it so for deserialize we can use this type directly
// and not have to specify the lifetime
pub type TransactionResponse = RPCTransaction<'static>;

#[derive(Serialize, Deserialize)]
pub struct SplitAddressParams {
    // address which must be in integrated form
    pub address: Address
}

#[derive(Serialize, Deserialize)]
pub struct SplitAddressResult {
    // Normal address
    pub address: Address,
    // Encoded data from address
    pub integrated_data: DataElement,
    // Integrated data size
    pub size: usize
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type", content = "value")]
pub enum RPCContractLog<'a> {
    RefundGas {
        amount: u64
    },
    Transfer {
        contract: Cow<'a, Hash>,
        amount: u64,
        asset: Cow<'a, Hash>,
        destination: Cow<'a, Address>
    },
    TransferContract {
        // Contract from which the asset is transferred
        contract: Cow<'a, Hash>,
        amount: u64,
        asset: Cow<'a, Hash>,
        // Destination contract
        destination: Cow<'a, Hash>
    },
    Mint {
        // Contract minter
        contract: Cow<'a, Hash>,
        asset: Cow<'a, Hash>,
        amount: u64
    },
    Burn {
        // Contract burner
        contract: Cow<'a, Hash>,
        asset: Cow<'a, Hash>,
        amount: u64
    },
    NewAsset {
        // Contract creator
        contract: Cow<'a, Hash>,
        asset: Cow<'a, Hash>
    },
    ExitCode(Option<u64>),
    RefundDeposits,
    GasInjection {
        // Contract from which gas is injected
        contract: Cow<'a, Hash>,
        amount: u64,
    },
    ScheduledExecution {
        contract: Cow<'a, Hash>,
        hash: Cow<'a, Hash>,
        kind: ScheduledExecutionKind,
    }
}

impl<'a> RPCContractLog<'a> {
    pub fn from_output_owned(output: ContractLog, mainnet: bool) -> Self {
        match output {
            ContractLog::RefundGas { amount } => RPCContractLog::RefundGas { amount: amount },
            ContractLog::Transfer { contract, amount, asset, destination } => RPCContractLog::Transfer {
                contract: Cow::Owned(contract),
                amount,
                asset: Cow::Owned(asset),
                destination: Cow::Owned(destination.as_address(mainnet))
            },
            ContractLog::TransferContract { contract, amount, asset, destination } => RPCContractLog::TransferContract {
                contract: Cow::Owned(contract),
                amount,
                asset: Cow::Owned(asset),
                destination: Cow::Owned(destination)
            },
            ContractLog::Mint { contract, asset, amount } => RPCContractLog::Mint {
                contract: Cow::Owned(contract),
                asset: Cow::Owned(asset),
                amount
            },
            ContractLog::Burn { contract, asset, amount } => RPCContractLog::Burn {
                contract: Cow::Owned(contract),
                asset: Cow::Owned(asset),
                amount
            },
            ContractLog::NewAsset { contract, asset } => RPCContractLog::NewAsset {
                contract: Cow::Owned(contract),
                asset: Cow::Owned(asset)
            },
            ContractLog::ExitCode(code) => RPCContractLog::ExitCode(code.clone()),
            ContractLog::RefundDeposits => RPCContractLog::RefundDeposits,
            ContractLog::GasInjection { contract, amount } => RPCContractLog::GasInjection { contract: Cow::Owned(contract), amount },
            ContractLog::ScheduledExecution { contract, hash, kind } => RPCContractLog::ScheduledExecution {
                contract: Cow::Owned(contract),
                hash: Cow::Owned(hash),
                kind
            },
        }
    }
    pub fn from_output(output: &'a ContractLog, mainnet: bool) -> Self {
        match output {
            ContractLog::RefundGas { amount } => RPCContractLog::RefundGas { amount: *amount },
            ContractLog::Transfer { contract, amount, asset, destination } => RPCContractLog::Transfer {
                contract: Cow::Borrowed(contract),
                amount: *amount,
                asset: Cow::Borrowed(asset),
                destination: Cow::Owned(destination.as_address(mainnet))
            },
            ContractLog::TransferContract { contract, amount, asset, destination } => RPCContractLog::TransferContract {
                contract: Cow::Borrowed(contract),
                amount: *amount,
                asset: Cow::Borrowed(asset),
                destination: Cow::Borrowed(destination)
            },
            ContractLog::Mint { contract, asset, amount } => RPCContractLog::Mint {
                contract: Cow::Borrowed(contract),
                asset: Cow::Borrowed(asset),
                amount: *amount
            },
            ContractLog::Burn { contract, asset, amount } => RPCContractLog::Burn {
                contract: Cow::Borrowed(contract),
                asset: Cow::Borrowed(asset),
                amount: *amount
            },
            ContractLog::NewAsset { contract, asset } => RPCContractLog::NewAsset {
                contract: Cow::Borrowed(contract),
                asset: Cow::Borrowed(asset)
            },
            ContractLog::ExitCode(code) => RPCContractLog::ExitCode(code.clone()),
            ContractLog::RefundDeposits => RPCContractLog::RefundDeposits,
            ContractLog::GasInjection { contract, amount } => RPCContractLog::GasInjection { contract: Cow::Borrowed(contract), amount: *amount },
            ContractLog::ScheduledExecution { contract, hash, kind } => RPCContractLog::ScheduledExecution {
                contract: Cow::Borrowed(contract),
                hash: Cow::Borrowed(hash),
                kind: *kind
            },
        }
    }
}
impl<'a> From<RPCContractLog<'a>> for ContractLog {
    fn from(output: RPCContractLog<'a>) -> Self {
        match output {
            RPCContractLog::RefundGas { amount } => ContractLog::RefundGas { amount },
            RPCContractLog::Transfer { contract, amount, asset, destination } => ContractLog::Transfer {
                contract: contract.into_owned(),
                amount,
                asset: asset.into_owned(),
                destination: destination.into_owned().to_public_key()
            },
            RPCContractLog::TransferContract { contract, amount, asset, destination } => ContractLog::TransferContract {
                contract: contract.into_owned(),
                amount,
                asset: asset.into_owned(),
                destination: destination.into_owned()
            },
            RPCContractLog::Mint { contract, asset, amount } => ContractLog::Mint {
                contract: contract.into_owned(),
                asset: asset.into_owned(),
                amount
            },
            RPCContractLog::Burn { contract, asset, amount } => ContractLog::Burn {
                contract: contract.into_owned(),
                asset: asset.into_owned(),
                amount
            },
            RPCContractLog::NewAsset { contract, asset } => ContractLog::NewAsset {
                contract: contract.into_owned(),
                asset: asset.into_owned()
            },
            RPCContractLog::ExitCode(code) => ContractLog::ExitCode(code),
            RPCContractLog::RefundDeposits => ContractLog::RefundDeposits,
            RPCContractLog::GasInjection { contract, amount } => ContractLog::GasInjection {
                contract: contract.into_owned(),
                amount
            },
            RPCContractLog::ScheduledExecution { contract, hash, kind } => ContractLog::ScheduledExecution {
                contract: contract.into_owned(),
                hash: hash.into_owned(),
                kind
            }
        }
    }
}

// :(
// We are forced to create function for the default value path requested by serde
fn default_true_value() -> bool {
    true
}

// same here
fn default_false_value() -> bool {
    false
}