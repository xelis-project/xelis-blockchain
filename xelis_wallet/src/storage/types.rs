use std::{borrow::{Borrow, Cow}, collections::HashSet, hash};

use serde::{Deserialize, Serialize};
use xelis_common::{
    account::CiphertextCache,
    block::TopoHeight,
    crypto::Hash,
    serializer::{
        Reader,
        ReaderError,
        Serializer,
        Writer
    },
    api::wallet::TransactionPending as RPCTransactionPending,
    time::TimestampMillis,
    transaction::{MultiSigPayload, Reference}
};

use crate::entry::EntryData;


#[derive(Debug, Clone)]
pub struct Balance {
    pub amount: u64,
    pub ciphertext: CiphertextCache,
    pub topoheight: TopoHeight,
}

impl Balance {
    pub fn new(amount: u64, ciphertext: CiphertextCache, topoheight: TopoHeight) -> Self {
        Self {
            amount,
            ciphertext,
            topoheight
        }
    }
}

impl Serializer for Balance {
    fn write(&self, writer: &mut Writer) {
        self.amount.write(writer);
        self.ciphertext.write(writer);
        self.topoheight.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let amount = u64::read(reader)?;
        let ciphertext = CiphertextCache::read(reader)?;
        let topoheight = TopoHeight::read(reader)?;
        Ok(Self {
            amount,
            ciphertext,
            topoheight,
        })
    }
}


#[derive(Debug, Clone)]
pub struct TxCache {
    // This is used to store the nonce used to create new transactions
    pub nonce: u64,
    // Last reference used to build a transaction
    pub reference: Reference,
    // Last transaction hash created
    // This is used to determine if we should erase the last unconfirmed balance or not
    pub last_tx_hash_created: Option<Hash>,
    // Set of assets used in the last transaction
    pub assets: HashSet<Hash>,
}

// A multisig state in the wallet DB
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiSig {
    pub payload: MultiSigPayload,
    pub topoheight: TopoHeight,
}

impl Serializer for MultiSig {
    fn write(&self, writer: &mut Writer) {
        self.payload.write(writer);
        self.topoheight.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let payload = MultiSigPayload::read(reader)?;
        let topoheight = TopoHeight::read(reader)?;
        Ok(Self {
            payload,
            topoheight
        })
    }
}

#[derive(Clone, Debug)]
pub struct TransactionPending {
    // Transaction hash
    pub hash: Hash,
    // At which time the transaction was created
    pub timestamp: TimestampMillis,
    // Entry data of the transaction
    pub entry: EntryData,
}

impl hash::Hash for TransactionPending {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.hash.hash(state);
    }
}

impl PartialEq for TransactionPending {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl Eq for TransactionPending {}

impl Borrow<Hash> for TransactionPending {
    fn borrow(&self) -> &Hash {
        &self.hash
    }
}

impl TransactionPending {
    pub fn serializable(self, mainnet: bool) -> RPCTransactionPending<'static> {
        RPCTransactionPending {
            hash: Cow::Owned(self.hash),
            entry: self.entry.serializable(mainnet),
            timestamp: self.timestamp,
        }
    }
}