use crate::globals::{Hash, Hashable};
use std::collections::HashMap;

#[derive(Clone, serde::Serialize)]
pub struct Tx {
    pub amount: u64,
    pub to: String
}

#[derive(Clone, serde::Serialize)]
pub struct SmartContractTx {
    pub contract: String,
    pub amount: u64,
    pub params: HashMap<String, String> //TODO
}

#[derive(Clone, serde::Serialize)]
pub struct BurnTx {
    pub amount: u64
}

#[derive(Clone, serde::Serialize)]
pub struct CoinbaseTx {
    pub block_reward: u64,
    pub fee: u64
}

#[derive(Clone, serde::Serialize)]
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
                bytes.extend(&tx.block_reward.to_be_bytes());
                bytes.extend(&tx.fee.to_be_bytes());
            }
        }
        bytes
    }
}

#[derive(Clone, serde::Serialize)]
pub struct Transaction { //TODO implement signature
    hash: Hash,
    nonce: u64,
    data: TransactionData,
    sender: String,
    fee: u64
}

impl Transaction {

    pub fn new(nonce: u64, data: TransactionData, sender: String) -> Self {
        let mut tx = Transaction {
            hash: [0; 32],
            nonce,
            data,
            sender,
            fee: 0
        };
        tx.fee = if tx.is_coinbase() { 0 } else { crate::blockchain::calculate_tx_fee(tx.size()) };
        tx
    }

    pub fn get_hash(&self) -> &Hash {
        &self.hash
    }

    pub fn get_nonce(&self) -> &u64 {
        &self.nonce
    }

    pub fn get_data(&self) -> &TransactionData {
        &self.data
    }

    pub fn get_sender(&self) -> &String {
        &self.sender
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
}

impl Hashable for Transaction {

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        bytes.extend(&self.nonce.to_be_bytes());
        bytes.extend(self.data.to_bytes());
        bytes.extend(self.sender.as_bytes());
        bytes.extend(&self.fee.to_be_bytes());

        bytes
    }
}