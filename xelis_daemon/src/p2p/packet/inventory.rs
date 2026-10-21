use std::borrow::Cow;
use indexmap::IndexSet;
use log::debug;
use xelis_common::{
    crypto::{Hash, HASH_SIZE},
    serializer::{
        DecodeError,
        Error as SerializationError,
        OptionNonZero,
        Readable,
        Reader,
        ReaderError,
        Serializer,
        Writable,
        Writer,
    },
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
    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            let page = OptionNonZero::<u8>::read(reader)?.0;
            Ok(Self::new(page))
        })
    }

    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| OptionNonZero(self.page).write(writer))
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

    pub fn len(&self) -> usize {
        self.txs.len()
    }
}

impl<'a> Serializer for NotifyInventoryResponse<'a> {
    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            let next = OptionNonZero::<u8>::read(reader)?.0;
            let count = u16::read(reader)?;
            if count > NOTIFY_MAX_LEN as u16 {
                return Err(SerializationError::new(DecodeError::InvalidSize).context(format!("inventory response contains {count} transaction hashes; maximum is {NOTIFY_MAX_LEN}")));
            }

            let mut txs = IndexSet::with_capacity(count as usize);
            for _ in 0..count {
                if !txs.insert(Cow::Owned(Hash::read(reader)?)) {
                    debug!("Duplicate transaction in NotifyInventoryResponse");
                    return Err(SerializationError::new(DecodeError::InvalidValue).context("duplicate transaction hash in inventory response"))
                }
            }
            Ok(Self::new(next, Cow::Owned(txs)))
        })
    }

    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            OptionNonZero(self.next).write(writer)?;
            (self.txs.len() as u16).write(writer)?;
            for tx in self.txs.iter() {
                tx.write(writer)?;
            }
            Ok(())
        })
    }

    fn size(&self) -> usize {
        1 + 2 + self.txs.len() * HASH_SIZE
    }
}