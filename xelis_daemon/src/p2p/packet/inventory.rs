use std::{borrow::Cow, collections::HashSet};

use xelis_common::{crypto::hash::Hash, serializer::{Serializer, ReaderError, Reader, Writer}};

pub const NOTIFY_MAX_LEN: usize = 512; // 512 * 32 bytes = 16KB

#[derive(Debug, Clone)]
pub struct NotifyInventory<'a> {
    txs: Cow<'a, HashSet<Cow<'a, Hash>>>,
}

impl<'a> NotifyInventory<'a> {
    pub fn new(txs: Cow<'a, HashSet<Cow<'a, Hash>>>) -> Self {
        Self { txs }
    }

    pub fn get_txs(self) -> Cow<'a, HashSet<Cow<'a, Hash>>> {
        self.txs
    }
}

impl<'a> Serializer for NotifyInventory<'a> {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let count = reader.read_u16()?;
        if count > NOTIFY_MAX_LEN as u16 {
            return Err(ReaderError::InvalidSize);
        }
 
        let mut txs = HashSet::with_capacity(count as usize);
        for _ in 0..count {
            txs.insert(Cow::Owned(reader.read_hash()?));
        }

        Ok(Self::new(Cow::Owned(txs)))
    }

    fn write(&self, writer: &mut Writer) {
        writer.write_u16(self.txs.len() as u16);
        for tx in self.txs.iter() {
            writer.write_hash(tx);
        }
    }
}