use crate::crypto::key::{PublicKey, Signature, SIGNATURE_LENGTH, KeyPair};
use crate::crypto::hash::{Hashable, hash};
use crate::wallet::WalletError;
use super::blockchain::calculate_tx_fee;
use super::reader::{Reader, ReaderError};
use super::error::BlockchainError;
use super::serializer::Serializer;
use super::writer::Writer;
use std::collections::HashMap;

#[derive(serde::Serialize, Clone)]
pub struct Transfer {
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
pub enum TransactionType {
    Normal(Vec<Transfer>),
    SmartContract(SmartContractTx),
    Burn(u64),
    UploadSmartContract(String),
}

#[derive(serde::Serialize, Clone)]
pub struct Transaction {
    owner: PublicKey,
    data: TransactionType,
    signature: Signature,
    fee: u64 // fees for this tx
}

pub struct TransactionBuilder {
    owner: PublicKey,
    data: TransactionType,
    fee_multiplier: f64
}

impl Serializer for TransactionType {
    fn write(&self, writer: &mut Writer) {
        match self {
            TransactionType::Burn(amount) => {
                writer.write_u8(0);
                writer.write_u64(amount);
            }
            TransactionType::Normal(txs) => {
                writer.write_u8(1);
                let len: u8 = txs.len() as u8; // max 255 txs
                writer.write_u8(len);
                for tx in txs {
                    writer.write_u64(&tx.amount);
                    tx.to.write(writer);
                }
            }
            TransactionType::SmartContract(tx) => {
                writer.write_u8(2);
                writer.write_string(&tx.contract);
                writer.write_u64(&tx.amount);

                writer.write_u8(tx.params.len() as u8); // maximum 255 params supported
                for (key, value) in &tx.params {
                    writer.write_string(key);
                    writer.write_string(value); // TODO real value type
                }
            }
            TransactionType::UploadSmartContract(code) => {
                writer.write_u8(3);
                writer.write_string(code);
            }
        };
    }

    fn read(reader: &mut Reader) -> Result<TransactionType, ReaderError> {
        Ok(match reader.read_u8()? {
            0 => {
                let amount = reader.read_u64()?;
                TransactionType::Burn(amount)
            },
            1 => { // Normal
                let mut txs = vec![];
                for _ in 0..reader.read_u8()? {
                    let amount = reader.read_u64()?;
                    let to = PublicKey::read(reader)?;

                    txs.push(Transfer {
                        amount,
                        to: to
                    });
                }
                TransactionType::Normal(txs)
            },
            2 => { // TODO SC
                todo!("Smart Contract TODO")
            },
            _ => {
                return Err(ReaderError::InvalidValue)
            }
        })
    }
}

impl Transaction {
    pub fn new(owner: PublicKey, data: TransactionType, signature: Signature, fee: u64) -> Self {
        Transaction {
            owner,
            data,
            signature,
            fee
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
        self.signature.write(writer);
        writer.write_u64(&self.fee);
    }

    fn read(reader: &mut Reader) -> Result<Transaction, ReaderError> {
        Ok(Transaction {
            owner: PublicKey::read(reader)?,
            data: TransactionType::read(reader)?,
            signature: Signature::read(reader)?,
            fee: reader.read_u64()?
        })
    }
}

impl Hashable for Transaction {}

impl TransactionBuilder {
    pub fn new(owner: PublicKey, data: TransactionType, fee_multiplier: f64) -> Self {
        Self {
            owner,
            data,
            fee_multiplier
        }
    }

    pub fn build(self, keypair: KeyPair) -> Result<Transaction, WalletError> {
        if *keypair.get_public_key() != self.owner {
            return Err(WalletError::InvalidKeyPair)
        }

        if let TransactionType::Normal(txs) = &self.data {
            if txs.len() == 0 {
                return Err(WalletError::ExpectedOneTx)
            }

            for tx in txs {
                if tx.to == self.owner {
                    return Err(WalletError::TxOwnerIsReceiver)
                }
            }
        }

        let mut writer = Writer::new();
        self.owner.write(&mut writer);
        self.data.write(&mut writer);

        // 8 represent the field 'fee' in bytes size
        let total_bytes = SIGNATURE_LENGTH + 8 + writer.total_write();
        let fee = (calculate_tx_fee(total_bytes) as f64  * self.fee_multiplier) as u64;
        writer.write_u64(&fee);

        let signature = keypair.sign(&writer.bytes());
        let tx = Transaction::new(self.owner, self.data, signature, fee);

        Ok(tx)
    }
}