mod data;
pub mod wallet;
pub mod daemon;
pub mod query;

use std::borrow::Cow;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use bulletproofs::RangeProof;
use xelis_vm::Module;
use crate::{
    account::Nonce,
    crypto::{
        elgamal::{CompressedCommitment, CompressedHandle},
        proofs::CiphertextValidityProof,
        Address,
        Hash,
        Signature
    },
    serializer::Serializer,
    contract::ContractOutput,
    transaction::{
        extra_data::UnknownExtraDataFormat,
        multisig::MultiSig,
        BurnPayload,
        InvokeContractPayload,
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
    DeployContract(Cow<'a, Module>)
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
            TransactionType::DeployContract(module) => Self::DeployContract(Cow::Borrowed(module))
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
            RPCTransactionType::DeployContract(module) => TransactionType::DeployContract(module.into_owned())
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
    pub fn from_tx(tx: &'a Transaction, hash: &'a Hash, mainnet: bool) -> Self {
        Self {
            hash: Cow::Borrowed(hash),
            version: tx.get_version(),
            source: tx.get_source().as_address(mainnet),
            data: RPCTransactionType::from_type(tx.get_data(), mainnet),
            fee: tx.get_fee(),
            nonce: tx.get_nonce(),
            source_commitments: Cow::Borrowed(tx.get_source_commitments()),
            range_proof: Cow::Borrowed(tx.get_range_proof()),
            reference: Cow::Borrowed(tx.get_reference()),
            multisig: Cow::Borrowed(tx.get_multisig()),
            signature: Cow::Borrowed(tx.get_signature()),
            size: tx.size()
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
pub enum RPCContractOutput<'a> {
    RefundGas {
        amount: u64
    },
    Transfer {
        amount: u64,
        asset: Cow<'a, Hash>,
        destination: Cow<'a, Address>
    },
    ExitCode(Option<u64>),
    RefundDeposits
}

impl<'a> RPCContractOutput<'a> {
    pub fn from_output(output: ContractOutput, mainnet: bool) -> Self {
        match output {
            ContractOutput::RefundGas { amount } => RPCContractOutput::RefundGas { amount },
            ContractOutput::Transfer { amount, asset, destination } => RPCContractOutput::Transfer {
                amount,
                asset: Cow::Owned(asset),
                destination: Cow::Owned(destination.to_address(mainnet))
            },
            ContractOutput::ExitCode(code) => RPCContractOutput::ExitCode(code),
            ContractOutput::RefundDeposits => RPCContractOutput::RefundDeposits,
        }
    }
}

impl<'a> From<RPCContractOutput<'a>> for ContractOutput {
    fn from(output: RPCContractOutput<'a>) -> Self {
        match output {
            RPCContractOutput::RefundGas { amount } => ContractOutput::RefundGas { amount },
            RPCContractOutput::Transfer { amount, asset, destination } => ContractOutput::Transfer {
                amount,
                asset: asset.into_owned(),
                destination: destination.into_owned().to_public_key()
            },
            RPCContractOutput::ExitCode(code) => ContractOutput::ExitCode(code),
            RPCContractOutput::RefundDeposits => ContractOutput::RefundDeposits,
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