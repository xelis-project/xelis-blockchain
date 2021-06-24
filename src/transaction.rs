use crate::globals::{Hash, Hashable};
use std::collections::HashMap;

#[derive(Clone)]
pub struct Tx {
    pub amount: u64,
    pub to: String
}

#[derive(Clone)]
pub struct SmartContractTx {
    pub contract: String,
    pub amount: u64,
    pub params: HashMap<String, String> //TODO
}

#[derive(Clone)]
pub struct BurnTx {
    pub amount: u64
}

#[derive(Clone)]
pub struct CoinbaseTx {
    pub reward: u64
}

#[derive(Clone)]
pub enum TransactionData {
    Registration,
    Normal(Vec<Tx>),
    SmartContract(SmartContractTx),
    Burn(BurnTx),
    Coinbase(CoinbaseTx),
}

impl Hashable for TransactionData {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        match self {
            TransactionData::Burn(tx) => {
                bytes.push(0);
                bytes.extend(&tx.amount.to_be_bytes());
            }
            TransactionData::Normal(txs) => {
                bytes.push(1);
                bytes.extend(&txs.len().to_be_bytes());
                for tx in txs {
                    bytes.extend(&tx.amount.to_be_bytes());
                    bytes.extend(tx.to.as_bytes());
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
                bytes.extend(&tx.reward.to_be_bytes());
            }
        }
        bytes
    }
}

#[derive(Clone)]
pub struct Transaction { //TODO implement signature
    hash: Hash,
    nonce: u64,
    timestamp: u64,
    data: TransactionData,
    sender: String,
    fee: u64
}

impl Transaction {

    pub fn new(nonce: u64, timestamp: u64, data: TransactionData, sender: String, fee: u64) -> Self {
        Transaction {
            hash: [0; 32],
            nonce,
            timestamp,
            data,
            sender,
            fee
        }
    }

    pub fn get_hash(&self) -> &Hash {
        &self.hash
    }

    pub fn get_nonce(&self) -> &u64 {
        &self.nonce
    }

    pub fn get_timestamp(&self) -> &u64 {
        &self.timestamp
    }

    pub fn get_data(&self) -> &TransactionData {
        &self.data
    }

    pub fn get_sender(&self) -> &String {
        &self.sender
    }
}

impl Hashable for Transaction {

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend(&self.hash);
        bytes.extend(&self.nonce.to_be_bytes());
        bytes.extend(&self.timestamp.to_be_bytes());
        bytes.extend(self.data.to_bytes());
        bytes.extend(self.sender.as_bytes());

        bytes
    }
}