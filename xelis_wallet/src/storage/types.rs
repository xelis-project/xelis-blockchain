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
    transaction::{MultiSigPayload, Reference}
};


#[derive(Debug, Clone)]
pub struct Balance {
    pub amount: u64,
    pub ciphertext: CiphertextCache
}

impl Balance {
    pub fn new(amount: u64, ciphertext: CiphertextCache) -> Self {
        Self {
            amount,
            ciphertext
        }
    }
}

impl Serializer for Balance {
    fn write(&self, writer: &mut Writer) {
        self.amount.write(writer);
        self.ciphertext.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let amount = u64::read(reader)?;
        let ciphertext = CiphertextCache::read(reader)?;
        Ok(Self {
            amount,
            ciphertext
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
    pub last_tx_hash_created: Hash,
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