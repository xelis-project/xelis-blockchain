mod data;
pub mod wallet;
pub mod daemon;
pub mod query;

use std::borrow::Cow;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use bulletproofs::RangeProof;
use crate::{
    crypto::{
        elgamal::{CompressedCommitment, CompressedHandle},
        proofs::CiphertextValidityProof,
        Address,
        Hash,
        Signature
    },
    transaction::{
        aead::AEADCipher,
        BurnPayload,
        Reference,
        SourceCommitment,
        Transaction,
        TransactionType,
        TransferPayload
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
    pub extra_data: Cow<'a, Option<AEADCipher>>,
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
            TransactionType::Burn(burn) => Self::Burn(Cow::Borrowed(burn))
        }
    }
}

impl From<RPCTransactionType<'_>> for TransactionType {
    fn from(data: RPCTransactionType) -> Self {
        match data {
            RPCTransactionType::Transfers(transfers) => {
                TransactionType::Transfers(transfers.into_iter().map(|transfer| transfer.into()).collect::<Vec<TransferPayload>>())
            },
            RPCTransactionType::Burn(burn) => TransactionType::Burn(burn.into_owned())
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
    pub version: u8,
    // Source of the transaction
    pub source: Address,
    /// Type of the transaction
    pub data: RPCTransactionType<'a>,
    /// Fees in XELIS
    pub fee: u64,
    /// nonce must be equal to the one on chain account
    /// used to prevent replay attacks and have ordered transactions
    pub nonce: u64,
    /// We have one source commitment and equality proof per asset used in the tx.
    pub source_commitments: Cow<'a, Vec<SourceCommitment>>,
    /// The range proof is aggregated across all transfers and across all assets.
    pub range_proof: Cow<'a, RangeProof>,
    /// Reference at which block the transaction was built
    pub reference: Cow<'a, Reference>,
    /// Signature of the transaction
    pub signature: Cow<'a, Signature>,
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
            signature: Cow::Borrowed(tx.get_signature()),
        }
    }
}

impl<'a> From<RPCTransaction<'a>> for Transaction {
    fn from(tx: RPCTransaction<'a>) -> Self {
        Transaction::new(
            tx.source.to_public_key(),
            tx.data.into(),
            tx.fee,
            tx.nonce,
            tx.source_commitments.into_owned(),
            tx.range_proof.into_owned(),
            tx.reference.into_owned(),
            tx.signature.into_owned()
        )
    }
}

// We create a type above it so for deserialize we can use this type directly
// and not have to specify the lifetime
pub type TransactionResponse = RPCTransaction<'static>;