use crate::globals::{Hash, Hashable};
use crate::config::REGISTRATION_DIFFICULTY;
use crate::blockchain::BlockchainError;
use crate::difficulty::check_difficulty;
use std::collections::HashMap;
use ed25519_dalek::{Signature, PublicKey, Keypair, Verifier, Signer};

#[derive(Clone, Eq, PartialEq, serde::Serialize)]
pub struct Tx {
    pub amount: u64,
    pub to: PublicKey
}

#[derive(Clone, Eq, PartialEq, serde::Serialize)]
pub struct UploadSmartContractTx {
    pub code: String
}

#[derive(Clone, Eq, PartialEq, serde::Serialize)]
pub struct SmartContractTx {
    pub contract: String,
    pub amount: u64,
    pub params: HashMap<String, String> //TODO
}

#[derive(Clone, Eq, PartialEq, serde::Serialize)]
pub struct BurnTx {
    pub amount: u64
}

#[derive(Clone, Eq, PartialEq, serde::Serialize)]
pub struct CoinbaseTx {
    pub amount: u64
}

#[derive(Clone, Eq, PartialEq, serde::Serialize)]
pub enum TransactionData {
    Registration,
    Normal(Vec<Tx>),
    SmartContract(SmartContractTx),
    Burn(BurnTx),
    Coinbase(CoinbaseTx),
    UploadSmartContract(UploadSmartContractTx),
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
                bytes.extend(&tx.amount.to_be_bytes());
            }
            TransactionData::UploadSmartContract(tx) => {
                bytes.push(5);
                bytes.extend(tx.code.as_bytes());
            }
        }
        bytes
    }
}

#[derive(Clone, serde::Serialize)]
pub struct Transaction {
    hash: Hash,
    nonce: u64,
    data: TransactionData,
    sender: PublicKey,
    fee: u64,
    signature: Option<Signature>
}

impl Transaction {

    pub fn new(nonce: u64, data: TransactionData, sender: PublicKey) -> Self {
        let mut tx = Transaction {
            hash: Hash::zero(),
            nonce,
            data,
            sender,
            fee: 0,
            signature: None,
        };

        tx.fee = match &tx.data { //Registration & Coinbase tx have no fee
            TransactionData::Registration | TransactionData::Coinbase(_) => 0,
            _ => crate::blockchain::calculate_tx_fee(tx.size())
        };
        tx.hash = tx.hash();
        tx
    }

    pub fn new_registration(sender: PublicKey) -> Result<Self, BlockchainError> {
        let mut tx = Transaction {
            hash: Hash::zero(),
            nonce: 0,
            data: TransactionData::Registration,
            sender,
            fee: 0,
            signature: None,
        };

        tx.calculate_hash()?;
        Ok(tx)
    }

    pub fn is_valid_signature(&self) -> bool {
        match self.signature {
            Some(v) => self.sender.verify(&self.hash.as_bytes(), &v).is_ok(),
            None => false
        }
    }

    pub fn has_signature(&self) -> bool {
        self.signature.is_some()
    }

    pub fn sign_transaction(&mut self, keypair: &Keypair) -> Result<(), BlockchainError> {
        if keypair.public != self.sender {
            return Err(BlockchainError::InvalidTransactionSignature);
        }

        self.signature = Some(keypair.sign(&self.hash.as_bytes()));

        Ok(())
    }

    pub fn calculate_hash(&mut self) -> Result<(), BlockchainError> {
        self.hash = match self.data {
            TransactionData::Registration => { //mini PoW for registration TX to prevent spam
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

        Ok(())
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

    pub fn get_sender(&self) -> &PublicKey {
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
            Some(v) => v.to_bytes().len(),
            None => 0,
        };
        
        size
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        bytes.extend(&self.nonce.to_be_bytes());
        bytes.extend(self.data.to_bytes());
        bytes.extend(&self.sender.to_bytes());
        bytes.extend(&self.fee.to_be_bytes());
        //TODO add signature

        bytes
    }
}