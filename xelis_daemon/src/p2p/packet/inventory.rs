use std::borrow::Cow;
use indexmap::IndexSet;
use log::debug;
use xelis_common::{
    crypto::{Hash, HASH_SIZE},
    serializer::{
        Serializer,
        ReaderError,
        Reader,
        Writer
    }
};

pub const NOTIFY_MAX_LEN: usize = 16384; // 16384 * 32 bytes = 512 KiB

#[derive(Debug, Clone)]
pub struct NotifyInventoryRequest {
    page: Option<u8>,
}

impl NotifyInventoryRequest {
    pub fn new(page: Option<u8>) -> Self {
        Self {
            page
        }
    }

    pub fn page(self) -> Option<u8> {
        self.page
    }
}

impl Serializer for NotifyInventoryRequest {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let page = reader.read_optional_non_zero_u8()?;
        Ok(Self::new(page))
    }

    fn write(&self, writer: &mut Writer) {
        writer.write_optional_non_zero_u8(self.page);
    }

    fn size(&self) -> usize {
        1
    }
}

#[derive(Debug)]
pub struct NotifyInventoryResponse<'a> {
    next: Option<u8>,
    txs: Cow<'a, IndexSet<Cow<'a, Hash>>>,
}

impl<'a> NotifyInventoryResponse<'a> {
    pub fn new(next: Option<u8>, txs: Cow<'a, IndexSet<Cow<'a, Hash>>>) -> Self {
        Self {
            next,
            txs
        }
    }

    pub fn next(&self) -> Option<u8> {
        self.next
    }

    pub fn get_txs(self) -> Cow<'a, IndexSet<Cow<'a, Hash>>> {
        self.txs
    }
}

impl<'a> Serializer for NotifyInventoryResponse<'a> {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let next = reader.read_optional_non_zero_u8()?;
        let count = reader.read_u16()?;
        if count > NOTIFY_MAX_LEN as u16 {
            return Err(ReaderError::InvalidSize);
        }
 
        let mut txs = IndexSet::with_capacity(count as usize);
        for _ in 0..count {
            if !txs.insert(Cow::Owned(reader.read_hash()?)) {
                debug!("Duplicate transaction in NotifyInventoryResponse");
                return Err(ReaderError::InvalidValue)
            }
        }
        Ok(Self::new(next, Cow::Owned(txs)))
    }

    fn write(&self, writer: &mut Writer) {
        writer.write_optional_non_zero_u8(self.next);
        writer.write_u16(self.txs.len() as u16);
        for tx in self.txs.iter() {
            writer.write_hash(tx);
        }
    }

    fn size(&self) -> usize {
        1 + 2 + self.txs.len() * HASH_SIZE
    }
}