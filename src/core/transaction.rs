use crate::crypto::key::{PublicKey, Signature, SIGNATURE_LENGTH, KeyPair};
use crate::crypto::hash::{Hashable, hash};
use super::reader::{Reader, ReaderError};
use super::error::BlockchainError;
use super::serializer::Serializer;
use super::writer::Writer;
use std::collections::HashMap;

#[derive(serde::Serialize, Clone)]
pub struct Tx {
    pub amount: u64,
    pub to: PublicKey
}

#[derive(serde::Serialize, Clone)]
pub struct SmartContractTx {
    pub contract: String,
    pub amount: u64,
    pub params: HashMap<String, String> // TODO
}

#[derive(serde::Serialize, Clone)]
pub enum TransactionData {
    Normal(Vec<Tx>),
    SmartContract(SmartContractTx),
    Burn(u64),
    UploadSmartContract(String),
}

impl Serializer for TransactionData {
    fn write(&self, writer: &mut Writer) {
        match self {
            TransactionData::Burn(amount) => {
                writer.write_u8(0);
                writer.write_u64(amount);
            }
            TransactionData::Normal(txs) => {
                writer.write_u8(1);
                let len: u8 = txs.len() as u8; // max 255 txs
                writer.write_u8(len);
                for tx in txs {
                    writer.write_u64(&tx.amount);
                    tx.to.write(writer);
                }
            }
            TransactionData::SmartContract(tx) => {
                writer.write_u8(2);
                writer.write_string(&tx.contract);
                writer.write_u64(&tx.amount);

                writer.write_u8(tx.params.len() as u8); // maximum 255 params supported
                for (key, value) in &tx.params {
                    writer.write_string(key);
                    writer.write_string(value); // TODO real value type
                }
            }
            TransactionData::UploadSmartContract(code) => {
                writer.write_u8(3);
                writer.write_string(code);
            }
        };
    }

    fn read(reader: &mut Reader) -> Result<TransactionData, ReaderError> {
        Ok(match reader.read_u8()? {
            0 => {
                let amount = reader.read_u64()?;
                TransactionData::Burn(amount)
            },
            1 => { // Normal
                let mut txs = vec![];
                for _ in 0..reader.read_u8()? {
                    let amount = reader.read_u64()?;
                    let to = PublicKey::read(reader)?;

                    txs.push(Tx {
                        amount,
                        to: to
                    });
                }
                TransactionData::Normal(txs)
            },
            2 => { // TODO SC
                TransactionData::SmartContract(SmartContractTx {
                    contract: String::from(""),
                    amount: 0,
                    params: HashMap::new()
                })
            },
            _ => {
                return Err(ReaderError::InvalidValue)
            }
        })
    }
}

#[derive(serde::Serialize, Clone)]
pub enum TransactionVariant {
    Normal {
        nonce: u64,
        fee: u64,
        data: TransactionData,
    },
    Registration,
    Coinbase,
}

impl Serializer for TransactionVariant {
    fn write(&self, writer: &mut Writer) {
        match self {
            TransactionVariant::Normal { nonce, fee, data } => {
                writer.write_u8(0);
                writer.write_u64(nonce);
                writer.write_u64(fee);
                data.write(writer);
            },
            TransactionVariant::Registration => {
                writer.write_u8(1);
            },
            TransactionVariant::Coinbase => {
                writer.write_u8(2);
            }
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let id = reader.read_u8()?;
        Ok(match id {
            0 => {
                let nonce = reader.read_u64()?;
                let fee = reader.read_u64()?;
                let data = TransactionData::read(reader)?;
                TransactionVariant::Normal { nonce, fee, data }
            },
            1 => {
                TransactionVariant::Registration
            }
            2 => {
                TransactionVariant::Coinbase
            }
            _ => return Err(ReaderError::InvalidValue)
        })
    }
}

#[derive(serde::Serialize, Clone)]
pub struct Transaction {
    owner: PublicKey,
    variant: TransactionVariant,
    signature: Option<Signature>
}

impl Transaction {
    pub fn new(owner: PublicKey, variant: TransactionVariant) -> Self {
        Transaction {
            owner,
            variant,
            signature: None
        }
    }

    pub fn get_variant(&self) -> &TransactionVariant {
        &self.variant
    }

    pub fn get_owner(&self) -> &PublicKey {
        &self.owner
    }

    pub fn is_coinbase(&self) -> bool {
        match self.get_variant() {
            TransactionVariant::Coinbase => true,
            _ => false
        }
    }

    pub fn require_signature(&self) -> bool { // TODO Require Signature for Registration to prevent random bytes
        match self.get_variant() {
            TransactionVariant::Normal { .. } => true,
            _ => false
        }
    }

    // check if we need a signature, and verify the validity of the signature if required
    pub fn verify_signature(&self) -> Result<bool, BlockchainError> {
        if let Some(signature) = &self.signature {
            if !self.require_signature() { // we shouldn't have a signature on unrequired variant
                return Err(BlockchainError::UnexpectedTransactionSignature)
            }

            let bytes = self.to_bytes();
            let bytes = &bytes[0..bytes.len() - SIGNATURE_LENGTH]; // remove signature bytes for verification
            Ok(self.get_owner().verify_signature(&hash(bytes), signature))
        } else if self.require_signature() { // we shouldn't have a signature on unrequired variant
            Err(BlockchainError::NoTxSignature)
        } else {
            Ok(true)
        }
    }

    pub fn sign(&mut self, pair: &KeyPair) {
        self.signature = Some(pair.sign(self.hash().as_bytes()));
    }

    pub fn set_fee(&mut self, value: u64) -> Result<(), BlockchainError> {
        if let TransactionVariant::Normal { ref mut fee, .. } = &mut self.variant {
            *fee = value;
            Ok(())
        } else {
            Err(BlockchainError::UnexpectedTransactionVariant)
        }
    }
}

impl Serializer for Transaction {
    fn write(&self, writer: &mut Writer) {
        self.owner.write(writer);
        self.variant.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Transaction, ReaderError> {
        let tx = Transaction {
            owner: PublicKey::read(reader)?,
            variant: TransactionVariant::read(reader)?,
            signature: None
        };


        Ok(tx)
    }
}

impl Hashable for Transaction {}