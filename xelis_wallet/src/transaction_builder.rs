use xelis_common::{
    transaction::{Transaction, TransactionType},
    globals::calculate_tx_fee,
    serializer::{Writer, Serializer},
    crypto::key::{SIGNATURE_LENGTH, PublicKey, KeyPair}
};

use crate::wallet::WalletError;

pub struct TransactionBuilder {
    owner: PublicKey,
    data: TransactionType,
    fee_multiplier: f64
}

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

        let mut writer = Writer::new();
        self.owner.write(&mut writer);
        self.data.write(&mut writer);

        // 8 represent the field 'fee' in bytes size
        let total_bytes = SIGNATURE_LENGTH + 8 + writer.total_write();
        let fee = (calculate_tx_fee(total_bytes) as f64  * self.fee_multiplier) as u64;
        let nonce = 0;
        writer.write_u64(&fee);

        let signature = keypair.sign(&writer.bytes());
        let tx = Transaction::new(self.owner, self.data, fee, nonce, signature);

        Ok(tx)
    }
}