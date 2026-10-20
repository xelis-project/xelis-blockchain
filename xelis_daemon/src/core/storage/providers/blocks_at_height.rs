use std::borrow::Cow;
use async_trait::async_trait;
use indexmap::IndexSet;
use log::error;
use xelis_common::{
    crypto::{Hash, HASH_SIZE},
    serializer::{
        DecodeError,
        Error as SerializationError,
        Readable,
        Reader,
        ReaderError,
        ReaderExt,
        Serializer,
        Writable,
        Writer,
    },
};
use crate::core::error::BlockchainError;

// This struct is used to store the blocks hashes at a specific height
// We use an IndexSet to store the hashes and maintains the order we processed them
#[derive(Default)]
pub struct OrderedHashes<'a>(pub Cow<'a, IndexSet<Hash>>);

#[async_trait]
pub trait BlocksAtHeightProvider {
    // Check if there are blocks at a specific height
    async fn has_blocks_at_height(&self, height: u64) -> Result<bool, BlockchainError>;

    // Retrieve the blocks hashes at a specific height
    async fn get_blocks_at_height(&self, height: u64) -> Result<IndexSet<Hash>, BlockchainError>;

    // This is used to store the blocks hashes at a specific height
    async fn set_blocks_at_height(&mut self, tips: &IndexSet<Hash>, height: u64) -> Result<(), BlockchainError>;

    // Append a block hash at a specific height
    async fn add_block_hash_at_height(&mut self, hash: &Hash, height: u64) -> Result<(), BlockchainError>;

    // Remove a block hash at a specific height
    async fn remove_block_hash_at_height(&mut self, hash: &Hash, height: u64) -> Result<(), BlockchainError>;
}

impl Serializer for OrderedHashes<'_> {
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            for hash in self.0.iter() {
                hash.write(writer)?;
            }
            Ok(())
        })
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            let bytes = reader.read_all_bytes()?;
            let total_size = bytes.len();
            let reader = &mut Reader::new(bytes.as_slice());
            if total_size % HASH_SIZE != 0 {
                error!("Invalid size: {}, expected a multiple of 32 for hashes", total_size);
                return Err(SerializationError::new(DecodeError::InvalidSize).context(format!("blocks at height byte length {total_size} must be a multiple of {HASH_SIZE}")))
            }

            let count = total_size / HASH_SIZE;
            let mut hashes = IndexSet::with_capacity(count);
            for _ in 0..count {
                hashes.insert(Hash::read(reader)?);
            }

            if hashes.len() != count {
                error!("Invalid size: received {} elements while sending {}", hashes.len(), count);
                return Err(SerializationError::new(DecodeError::InvalidSize).context("duplicate block hash in blocks at height")) 
            }

            Ok(OrderedHashes(Cow::Owned(hashes)))
        })
    }
}