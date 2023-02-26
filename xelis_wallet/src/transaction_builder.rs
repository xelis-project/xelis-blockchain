use std::collections::HashMap;

use xelis_common::{
    transaction::{Transaction, TransactionType, EXTRA_DATA_LIMIT_SIZE},
    globals::calculate_tx_fee,
    serializer::{Writer, Serializer},
    crypto::{key::{SIGNATURE_LENGTH, PublicKey, KeyPair}, hash::Hash}
};

use crate::wallet::WalletError;

pub struct TransactionBuilder {
    owner: PublicKey,
    data: TransactionType,
    nonce: u64,
    fee_multiplier: f64,
}

impl TransactionBuilder {
    pub fn new(owner: PublicKey, data: TransactionType, nonce: u64, fee_multiplier: f64) -> Self {
        Self {
            owner,
            data,
            nonce,
            fee_multiplier
        }
    }

    fn serialize(&self) -> Writer {
        let mut writer = Writer::new();
        self.owner.write(&mut writer);
        self.data.write(&mut writer);
        writer
    }

    fn estimate_fees_internal(&self, writer: &Writer) -> u64 {
        // 8 represent the field 'fee' in bytes size
        let total_bytes = SIGNATURE_LENGTH + 8 + writer.total_write();
        let fee = (calculate_tx_fee(total_bytes) as f64  * self.fee_multiplier) as u64;
        fee
    }

    pub fn total_spent(&self) -> HashMap<&Hash, u64> {
        let mut total_spent = HashMap::new();
        match &self.data {
            TransactionType::Burn(asset, amount) => {
                total_spent.insert(asset, *amount);
            },
            TransactionType::CallContract(call) => {
                for (asset, amount) in &call.assets {
                    total_spent.insert(asset, *amount);
                }
            },
            TransactionType::Transfer(txs) => {
                for tx in txs {
                    let current = total_spent.entry(&tx.asset).or_insert(0);
                    *current += tx.amount; 
                }
            },
            TransactionType::DeployContract(_) => {}
        }

        total_spent
    }

    pub fn total_extra_data_size(&self) -> usize {
        let mut total_size = 0;
        if let TransactionType::Transfer(txs) = &self.data {
            for tx in txs {
                if let Some(data) = &tx.extra_data {
                    total_size += data.len();
                }
            }
        }
        total_size
    }

    pub fn estimate_fees(&self) -> u64 {
        let writer = self.serialize();
        self.estimate_fees_internal(&writer)
    }

    pub fn build(self, keypair: &KeyPair) -> Result<Transaction, WalletError> {
        if *keypair.get_public_key() != self.owner {
            return Err(WalletError::InvalidKeyPair)
        }

        if let TransactionType::Transfer(txs) = &self.data {
            if txs.len() == 0 {
                return Err(WalletError::ExpectedOneTx)
            }

            for tx in txs {
                if tx.to == self.owner {
                    return Err(WalletError::TxOwnerIsReceiver)
                }
            }
        }

        let extra_data_size = self.total_extra_data_size();
        if extra_data_size > EXTRA_DATA_LIMIT_SIZE {
            return Err(WalletError::ExtraDataTooBig(EXTRA_DATA_LIMIT_SIZE, extra_data_size))
        }

        let mut writer = self.serialize();
        let fee = self.estimate_fees_internal(&writer);
        writer.write_u64(&fee);

        let signature = keypair.sign(&writer.bytes());
        let tx = Transaction::new(self.owner, self.data, fee, self.nonce, signature);

        Ok(tx)
    }
}