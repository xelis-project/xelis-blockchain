use crate::crypto::key::{PublicKey, KeyPair, Signature, SIGNATURE_LENGTH};
use crate::crypto::hash::{Hash, Hashable, hash};
use crate::config::REGISTRATION_DIFFICULTY;
use super::reader::{Reader, ReaderError};
use super::difficulty::check_difficulty;
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
pub struct CoinbaseTx {
    pub block_reward: u64,
    pub fee_reward: u64
}

#[derive(serde::Serialize, Clone)]
pub struct SmartContractTx {
    pub contract: String,
    pub amount: u64,
    pub params: HashMap<String, String> // TODO
}

#[derive(serde::Serialize, Clone)]
pub enum TransactionData {
    Registration,
    Normal(Vec<Tx>),
    SmartContract(SmartContractTx),
    Burn(u64),
    Coinbase(CoinbaseTx),
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
            TransactionData::Registration => {
                writer.write_u8(2);
            }
            TransactionData::SmartContract(tx) => {
                writer.write_u8(3);
                writer.write_string(&tx.contract);
                writer.write_u64(&tx.amount);

                writer.write_u8(tx.params.len() as u8); // maximum 255 params supported
                for (key, value) in &tx.params {
                    writer.write_string(key);
                    writer.write_string(value); // TODO real value type
                }
            }
            TransactionData::Coinbase(tx) => {
                writer.write_u8(4);
                writer.write_u64(&tx.block_reward);
                writer.write_u64(&tx.fee_reward);
            }
            TransactionData::UploadSmartContract(code) => {
                writer.write_u8(5);
                writer.write_string(code);
            }
        };
    }

    fn read(reader: &mut Reader) -> Result<TransactionData, ReaderError> {
        let data: TransactionData = match reader.read_u8()? {
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
            2 => { // Registration
                TransactionData::Registration
            },
            3 => { // TODO SC
                TransactionData::SmartContract(SmartContractTx {
                    contract: String::from(""),
                    amount: 0,
                    params: HashMap::new()
                })
            },
            4 => {
                let block_reward = reader.read_u64()?;
                let fee_reward = reader.read_u64()?;

                TransactionData::Coinbase(CoinbaseTx {
                    block_reward,
                    fee_reward
                })
            }
            _ => {
                return Err(ReaderError::InvalidValue)
            }
        };

        Ok(data)
    }
}

#[derive(serde::Serialize, Clone)]
pub struct Transaction {
    nonce: u64,
    data: TransactionData,
    owner: PublicKey,
    fee: u64,
    signature: Option<Signature>
}

impl Transaction {
    pub fn new(nonce: u64, data: TransactionData, owner: PublicKey) -> Self {
        let mut tx = Transaction {
            nonce,
            data,
            owner,
            fee: 0,
            signature: None,
        };

        tx.fee = match &tx.data { // Registration & Coinbase tx have no fee
            TransactionData::Registration | TransactionData::Coinbase(_) => 0,
            _ => crate::core::blockchain::calculate_tx_fee(tx.size())
        };

        tx
    }

    pub fn new_registration(owner: PublicKey) -> Result<Self, BlockchainError> {
        let mut tx = Transaction {
            nonce: 0,
            data: TransactionData::Registration,
            owner,
            fee: 0,
            signature: None,
        };

        tx.calculate_hash()?;
        Ok(tx)
    }

    pub fn verify_signature(&self) -> bool {
        match &self.signature {
            Some(signature) => {
                let bytes = self.to_bytes();
                let bytes = &bytes[0..bytes.len() - SIGNATURE_LENGTH]; // remove signature bytes for verification
                self.get_sender().verify_signature(&hash(bytes), signature)
            },
            None => false
        }
    }

    pub fn get_signature(&self) -> &Option<Signature> {
        &self.signature
    }

    pub fn has_signature(&self) -> bool { // registration & coinbase don't have signature.
        self.signature.is_some()
    }

    pub fn sign_transaction(&mut self, pair: &KeyPair) -> Result<(), BlockchainError> {
        self.signature = Some(pair.sign(self.hash().as_bytes()));

        Ok(())
    }

    pub fn calculate_hash(&mut self) -> Result<Hash, BlockchainError> {
        let result = match self.data {
            TransactionData::Registration => { //mini PoW for registration TX to prevent spam as we can't ask fee on newly created account
                let mut hash: Hash;
                loop {
                    hash = self.hash();
                    if check_difficulty(&hash, REGISTRATION_DIFFICULTY)? {
                        break;
                    } else {
                        self.nonce += 1;
                    }
                }

                hash
            }
            _ => {
                self.hash()
            }
        };

        Ok(result)
    }

    pub fn get_nonce(&self) -> u64 {
        self.nonce
    }

    pub fn get_data(&self) -> &TransactionData {
        &self.data
    }

    pub fn get_mut_data(&mut self) -> &mut TransactionData {
        &mut self.data
    }

    pub fn get_sender(&self) -> &PublicKey {
        &self.owner
    }

    pub fn get_fee(&self) -> u64 {
        self.fee
    }

    pub fn is_coinbase(&self) -> bool {
        match &self.data {
            TransactionData::Coinbase(_) => true,
            _ => false
        }
    }

    pub fn is_registration(&self) -> bool {
        match &self.data {
            TransactionData::Registration => true,
            _ => false 
        }
    }

    pub fn require_signature(&self) -> bool {
        match &self.data {
            TransactionData::Registration | TransactionData::Coinbase(_) => false,
            _ => true
        }
    }
}

impl Serializer for Transaction {
    fn write(&self, writer: &mut Writer) {
        writer.write_u64(&self.nonce); // 8
        self.data.write(writer); // 16 + 1 (coinbase tx)
        self.owner.write(writer); // 32
        writer.write_u64(&self.fee); // 8
        if let Some(signature) = &self.signature {
            signature.write(writer);
        }
    }

    fn read(reader: &mut Reader) -> Result<Transaction, ReaderError> {
        let nonce = reader.read_u64()?;
        let data = TransactionData::read(reader)?;
        let owner = PublicKey::read(reader)?;
        let fee = reader.read_u64()?;
        let signature: Option<Signature> = match &data {
            TransactionData::Registration | TransactionData::Coinbase(_) => None,
            _ => Some(Signature::read(reader)?)
        };

        Ok(Transaction {
            nonce,
            data: data,
            owner: owner,
            fee,
            signature
        })
    }
}

impl Hashable for Transaction {}