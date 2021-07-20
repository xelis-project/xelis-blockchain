use crate::crypto::hash::{Hash, Hashable};
use crate::crypto::key::{PublicKey, KeyPair, Signature, SIGNATURE_LENGTH};
use crate::config::REGISTRATION_DIFFICULTY;
use crate::blockchain::BlockchainError;
use crate::difficulty::check_difficulty;
use std::collections::HashMap;

#[derive(serde::Serialize)]
pub struct Tx {
    pub amount: u64,
    pub to: PublicKey
}

#[derive(serde::Serialize)]
pub struct CoinbaseTx {
    pub block_reward: u64,
    pub fee_reward: u64
}

#[derive(serde::Serialize)]
pub struct SmartContractTx {
    pub contract: String,
    pub amount: u64,
    pub params: HashMap<String, String> //TODO
}

#[derive(serde::Serialize)]
pub enum TransactionData {
    Registration,
    Normal(Vec<Tx>),
    SmartContract(SmartContractTx),
    Burn(u64),
    Coinbase(CoinbaseTx),
    UploadSmartContract(String),
}

impl Hashable for TransactionData {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        match self {
            TransactionData::Burn(amount) => {
                bytes.push(0);
                bytes.extend(&amount.to_be_bytes());
            }
            TransactionData::Normal(txs) => {
                bytes.push(1);
                bytes.extend(&txs.len().to_be_bytes());
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
}

#[derive(serde::Serialize)]
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

        tx.fee = match &tx.data { //Registration & Coinbase tx have no fee
            TransactionData::Registration | TransactionData::Coinbase(_) => 0,
            _ => crate::blockchain::calculate_tx_fee(tx.size())
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

    pub fn get_signature(&self) -> &Option<Signature> {
        &self.signature
    }

    pub fn has_signature(&self) -> bool {
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

    pub fn get_nonce(&self) -> &u64 {
        &self.nonce
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

    pub fn get_fee(&self) -> &u64 {
        &self.fee
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
}

impl Hashable for Transaction {

    fn size(&self) -> usize {
        let size = self.to_bytes().len() + match &self.signature {
            Some(_) => SIGNATURE_LENGTH,
            None => 0,
        };

        size
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        bytes.extend(&self.nonce.to_be_bytes());
        bytes.extend(self.data.to_bytes());
        bytes.extend(&self.owner.to_bytes());
        bytes.extend(&self.fee.to_be_bytes());
        //TODO add signature

        bytes
    }
}