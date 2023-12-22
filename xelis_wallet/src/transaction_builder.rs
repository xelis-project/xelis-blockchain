use std::collections::HashMap;

use xelis_common::{
    transaction::{Transaction, TransactionType, EXTRA_DATA_LIMIT_SIZE},
    utils::calculate_tx_fee,
    serializer::{Writer, Serializer},
    crypto::{key::{SIGNATURE_LENGTH, PublicKey, KeyPair}, hash::{Hash, hash}}, api::wallet::FeeBuilder
};

use crate::wallet::WalletError;

pub struct TransactionBuilder {
    owner: PublicKey,
    data: TransactionType,
    nonce: u64,
    fee_builder: FeeBuilder,
}

impl TransactionBuilder {
    pub fn new(owner: PublicKey, data: TransactionType, nonce: u64, fee_builder: FeeBuilder) -> Self {
        Self {
            owner,
            data,
            nonce,
            fee_builder
        }
    }

    fn serialize(&self) -> Writer {
        let mut writer = Writer::new();
        writer.write_u8(0);
        self.owner.write(&mut writer);
        self.data.write(&mut writer);
        writer
    }

    fn verify_fees_internal(&self, calculated_fees: u64) -> Result<u64, WalletError> {
        let provided_fees = match &self.fee_builder {
            FeeBuilder::Multiplier(multiplier) => (calculated_fees as f64  * multiplier) as u64,
            FeeBuilder::Value(value) => *value
        };

        if provided_fees < calculated_fees {
            return Err(WalletError::InvalidFeeProvided(calculated_fees, provided_fees))
        }

        Ok(provided_fees)
    }

    pub fn total_spent(&self) -> HashMap<&Hash, u64> {
        let mut total_spent = HashMap::new();
        match &self.data {
            TransactionType::Burn { asset, amount } => {
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

    fn estimate_fees_internal(&self, writer: &Writer) -> u64 {
        // 8 represent the field 'fee' in bytes size
        let total_bytes = SIGNATURE_LENGTH + 8 + writer.total_write();
        let calculated_fees = calculate_tx_fee(total_bytes);
        calculated_fees
    }

    pub fn estimate_fees(&self) -> u64 {
        let writer = self.serialize();
        self.estimate_fees_internal(&writer)
    }

    // Build the transaction and sign it with the provided keypair
    pub fn build(self, keypair: &KeyPair) -> Result<Transaction, WalletError> {
        if *keypair.get_public_key() != self.owner {
            return Err(WalletError::InvalidKeyPair)
        }

        if let TransactionType::Transfer(txs) = &self.data {
            if txs.len() == 0 {
                return Err(WalletError::ExpectedOneTx)
            }

            if txs.len() > u8::MAX as usize {
                return Err(WalletError::TooManyTx)
            }

            for tx in txs {
                if tx.to == self.owner {
                    return Err(WalletError::TxOwnerIsReceiver)
                }
            }
        }

        // Total extra data size must not exceed EXTRA_DATA_LIMIT_SIZE
        let extra_data_size = self.total_extra_data_size();
        if extra_data_size > EXTRA_DATA_LIMIT_SIZE {
            return Err(WalletError::ExtraDataTooBig(EXTRA_DATA_LIMIT_SIZE, extra_data_size))
        }

        let mut writer = self.serialize();
        let fee = self.verify_fees_internal(self.estimate_fees_internal(&writer))?;
        writer.write_u64(&fee);
        writer.write_u64(&self.nonce);

        let signature = keypair.sign(hash(writer.as_bytes()).as_bytes());
        let tx = Transaction::new(self.owner, self.data, fee, self.nonce, signature);

        if !tx.verify_signature() {
            return Err(WalletError::InvalidSignature)
        }

        Ok(tx)
    }
}