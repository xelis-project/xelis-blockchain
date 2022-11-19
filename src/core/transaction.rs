use crate::crypto::key::{PublicKey, Signature, SIGNATURE_LENGTH};
use crate::crypto::hash::{Hashable, hash, Hash};
use super::reader::{Reader, ReaderError};
use super::error::BlockchainError;
use super::serializer::Serializer;
use super::writer::Writer;
use std::collections::HashMap;

#[derive(serde::Serialize, Clone)]
pub struct Transfer {
    pub amount: u64,
    pub asset: Hash,
    pub to: PublicKey
}

#[derive(serde::Serialize, Clone)]
pub struct SmartContractCall {
    pub contract: Hash,
    pub assets: HashMap<Hash, u64>,
    pub params: HashMap<String, String> // TODO
}

// this enum represent all types of transaction available on XELIS Network
// you're able to send multi assets in one TX to different addresses
// you can burn one asset at a time (so the TX Hash can be used as unique proof)
// Smart Contract system is not yet available but types are already there
#[derive(serde::Serialize, Clone)]
pub enum TransactionType {
    Transfer(Vec<Transfer>),
    Burn(Hash, u64),
    CallContract(SmartContractCall),
    DeployContract(String), // represent the code to deploy
}

#[derive(serde::Serialize, Clone)]
pub struct Transaction {
    owner: PublicKey, // creator of this transaction
    data: TransactionType,
    fee: u64, // fees in XELIS for this tx
    nonce: u64, // nonce must be equal to the one on account
    signature: Signature // signature of this Transaction by the owner
}

impl Serializer for TransactionType {
    fn write(&self, writer: &mut Writer) {
        match self {
            TransactionType::Burn(asset, amount) => {
                writer.write_u8(0);
                writer.write_hash(asset);
                writer.write_u64(amount);
            }
            TransactionType::Transfer(txs) => {
                writer.write_u8(1);
                let len: u8 = txs.len() as u8; // max 255 txs
                writer.write_u8(len);
                for tx in txs {
                    writer.write_hash(&tx.asset);
                    writer.write_u64(&tx.amount);
                    tx.to.write(writer);
                }
            }
            TransactionType::CallContract(tx) => {
                writer.write_u8(2);
                writer.write_hash(&tx.contract);
                writer.write_u8(tx.assets.len() as u8); // maximum 255 assets per call
                for (asset, amount) in &tx.assets {
                    writer.write_hash(asset);
                    writer.write_u64(amount);
                }

                writer.write_u8(tx.params.len() as u8); // maximum 255 params supported
                for (key, value) in &tx.params {
                    writer.write_string(key);
                    writer.write_string(value); // TODO real value type
                }
            }
            TransactionType::DeployContract(code) => {
                writer.write_u8(3);
                writer.write_string(code);
            }
        };
    }

    fn read(reader: &mut Reader) -> Result<TransactionType, ReaderError> {
        Ok(match reader.read_u8()? {
            0 => {
                let asset = reader.read_hash()?;
                let amount = reader.read_u64()?;
                TransactionType::Burn(asset, amount)
            },
            1 => { // Normal
                let txs_count = reader.read_u8()?;
                let mut txs = Vec::with_capacity(txs_count as usize);
                for _ in 0..txs_count {
                    let asset = reader.read_hash()?;
                    let amount = reader.read_u64()?;
                    let to = PublicKey::read(reader)?;

                    txs.push(Transfer {
                        asset,
                        amount,
                        to
                    });
                }
                TransactionType::Transfer(txs)
            },
            2 => {
                let contract = reader.read_hash()?;
                let assets_count = reader.read_u8()?;
                let mut assets = HashMap::with_capacity(assets_count as usize);
                for _ in 0..assets_count {
                    let asset = reader.read_hash()?;
                    let amount = reader.read_u64()?;
                    assets.insert(asset, amount);
                }

                let params_count = reader.read_u8()?;
                let mut params = HashMap::with_capacity(params_count as usize);
                for _ in 0..params_count {
                    let key = reader.read_string()?;
                    let value = reader.read_string()?;
                    params.insert(key, value);
                }

                TransactionType::CallContract(SmartContractCall { contract, assets, params })
            },
            3 => {
                TransactionType::DeployContract(reader.read_string()?)
            }
            _ => {
                return Err(ReaderError::InvalidValue)
            }
        })
    }
}

impl Transaction {
    pub fn new(owner: PublicKey, data: TransactionType, fee: u64, nonce: u64, signature: Signature) -> Self {
        Transaction {
            owner,
            data,
            fee,
            nonce,
            signature
        }
    }

    pub fn get_owner(&self) -> &PublicKey {
        &self.owner
    }

    pub fn get_data(&self) -> &TransactionType {
        &self.data
    }
    
    pub fn get_fee(&self) -> u64 {
        self.fee
    }

    pub fn get_nonce(&self) -> u64 {
        self.nonce
    }

    // verify the validity of the signature
    pub fn verify_signature(&self) -> Result<bool, BlockchainError> {
        let bytes = self.to_bytes();
        let bytes = &bytes[0..bytes.len() - SIGNATURE_LENGTH]; // remove signature bytes for verification
        Ok(self.get_owner().verify_signature(&hash(bytes), &self.signature))
    }
}

impl Serializer for Transaction {
    fn write(&self, writer: &mut Writer) {
        self.owner.write(writer);
        self.data.write(writer);
        writer.write_u64(&self.fee);
        writer.write_u64(&self.nonce);
        self.signature.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Transaction, ReaderError> {
        Ok(Transaction {
            owner: PublicKey::read(reader)?,
            data: TransactionType::read(reader)?,
            fee: reader.read_u64()?,
            nonce: reader.read_u64()?,  
            signature: Signature::read(reader)?
        })
    }
}

impl Hashable for Transaction {}