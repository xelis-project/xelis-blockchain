use crate::crypto::hash::{Hash, Hashable, hash};
use crate::crypto::key::{PublicKey, KeyPair, Signature, SIGNATURE_LENGTH};
use crate::config::REGISTRATION_DIFFICULTY;
use super::error::BlockchainError;
use super::difficulty::check_difficulty;
use super::serializer::Serializer;
use super::reader::{Reader, ReaderError};
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
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        match self {
            TransactionData::Burn(amount) => {
                bytes.push(0);
                bytes.extend(&amount.to_be_bytes());
            }
            TransactionData::Normal(txs) => {
                bytes.push(1);
                let len: u8 = txs.len() as u8; // max 255 txs
                bytes.push(len);
                for tx in txs {
                    bytes.extend(&tx.amount.to_be_bytes());
                    bytes.extend(&tx.to.to_bytes());
                }
            }
            TransactionData::Registration => {
                bytes.push(2);
            }
            TransactionData::SmartContract(tx) => {
                bytes.push(3);
                bytes.extend(tx.contract.as_bytes());
                bytes.extend(&tx.amount.to_be_bytes());

                bytes.extend(&tx.params.len().to_be_bytes());
                for (key, value) in &tx.params {
                    bytes.extend(key.as_bytes());
                    bytes.extend(value.as_bytes())
                }
            }
            TransactionData::Coinbase(tx) => {
                bytes.push(4);
                bytes.extend(&tx.block_reward.to_be_bytes());
                bytes.extend(&tx.fee_reward.to_be_bytes());
            }
            TransactionData::UploadSmartContract(code) => {
                bytes.push(5);
                bytes.extend(code.as_bytes());
            }
        }
        bytes
    }

    fn from_bytes(reader: &mut Reader) -> Result<TransactionData, ReaderError> {
        let data: TransactionData = match reader.read_u8()? {
            0 => {
                let amount = reader.read_u64()?;
                TransactionData::Burn(amount)
            },
            1 => { // Normal
                let mut txs = vec![];
                for _ in 0..reader.read_u8()? {
                    let amount = reader.read_u64()?;
                    let to = PublicKey::from_bytes(reader)?;

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
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        bytes.extend(&self.nonce.to_be_bytes()); // 8
        bytes.extend(self.data.to_bytes()); // 16 + 1 (coinbase tx)
        bytes.extend(&self.owner.to_bytes()); // 32
        bytes.extend(&self.fee.to_be_bytes()); // 8
        match &self.signature {
            Some(signature) => {
                bytes.extend(&signature.to_bytes())
            },
            None => {}
        }

        bytes
    }

    fn from_bytes(reader: &mut Reader) -> Result<Transaction, ReaderError> {
        let nonce = reader.read_u64()?;
        let data = TransactionData::from_bytes(reader)?;
        let owner = PublicKey::from_bytes(reader)?;
        let fee = reader.read_u64()?;
        let signature: Option<Signature> = match &data {
            TransactionData::Registration | TransactionData::Coinbase(_) => None,
            _ => Some(Signature::from_bytes(reader)?)
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