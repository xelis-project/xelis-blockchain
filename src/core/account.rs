use std::sync::atomic::{AtomicU64, Ordering};

use super::{reader::{ReaderError, Reader}, serializer::Serializer, writer::Writer};


#[derive(serde::Serialize)]
pub struct Account {
    balance: AtomicU64,
    nonce: AtomicU64
}

impl Account {
    pub fn new(balance: u64, nonce: u64) -> Self {
        Self {
            balance: AtomicU64::new(balance),
            nonce: AtomicU64::new(nonce)
        }
    }

    pub fn get_balance(&self) -> &AtomicU64 {
        &self.balance
    }

    pub fn get_nonce(&self) -> &AtomicU64 {
        &self.nonce
    }

    pub fn read_balance(&self) -> u64 {
        self.balance.load(Ordering::Acquire)
    }

    pub fn read_nonce(&self) -> u64 {
        self.nonce.load(Ordering::Acquire)
    }
}

impl Serializer for Account {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let balance = reader.read_u64()?;
        let nonce = reader.read_u64()?;
        Ok(Self::new(balance, nonce))
    }

    fn write(&self, writer: &mut Writer) {
        writer.write_u64(&self.read_balance());
        writer.write_u64(&self.read_nonce());
    }
}