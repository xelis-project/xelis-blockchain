use std::collections::HashMap;

use async_trait::async_trait;
use linked_hash_table::LinkedHashMap;
use xelis_common::{
    crypto::Hash,
    serializer::*,
};
use crate::core::error::BlockchainError;

/// Represents the GHOSTDAG mergeset for a block, including the selected parent and its blues.
#[derive(Debug, Clone, Default)]
pub struct MergeSet {
    /// Blue blocks (ordered by insertion: SP first, then mergeset blues in coloring order).
    /// Empty for the genesis block.
    mergeset_blues: LinkedHashMap<Hash, usize>,
    
    /// Full anticone-size index for all blues (local + historical).
    /// Tracks how many blues from each block remain in anticone as coloring proceeds.
    /// This map is required for correct k-cluster violation detection.
    updated_anticones: HashMap<Hash, usize>,
}

impl MergeSet {
    /// Creates a new MergeSet with the given selected parent (SP) as the first blue.
    #[inline]
    pub fn new(selected_parent: Hash) -> Self {
        let mut mergeset_blues = LinkedHashMap::new();
        // SP has anticone size 0
        mergeset_blues.insert(selected_parent, 0);

        Self { mergeset_blues, updated_anticones: HashMap::new() }
    }

    /// Returns an iterator over all blue block hashes (SP first, then mergeset blues)
    #[inline]
    pub fn keys(&self) -> impl Iterator<Item = &Hash> {
        self.mergeset_blues.keys()
    }

    /// Returns an iterator over all blue blocks and their anticone sizes
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = (&Hash, usize)> {
        self.mergeset_blues.iter().map(|(hash, &size)| (hash, size))
    }

    /// Returns the number of blue blocks (SP + non-SP blues)
    #[inline]
    pub fn len(&self) -> usize {
        self.mergeset_blues.len()
    }

    /// Returns the anticone size of a blue block in the mergeset, or None if not found
    #[inline]
    pub fn get(&self, block: &Hash) -> Option<usize> {
        self.mergeset_blues.get(block)
            .or_else(|| self.updated_anticones.get(block))
            .copied()
    }

    /// Contains check for a blue block in the mergeset
    #[inline]
    pub fn contains(&self, block: &Hash) -> bool {
        self.mergeset_blues.contains_key(block)
    }

    /// Add a blue block to the mergeset and update anticone sizes.
    ///
    /// `blue_anticone_size` is the candidate's own anticone size.
    /// `affected_sizes` maps each existing blue (whose anticone grew)
    /// to its size *before* this addition - we store `size + 1`.
    pub fn add_blue(
        &mut self,
        block: Hash,
        blue_anticone_size: usize,
        affected_sizes: LinkedHashMap<Hash, usize>,
    ) {
        self.mergeset_blues.insert(block, blue_anticone_size);

        // Each affected blue gains one more block in its anticone.
        // This includes both mergeset blues and historical blues.
        for (blue, size) in affected_sizes {
            if let Some(entry) = self.mergeset_blues.get_mut(&blue) {
                *entry = size + 1;
            } else {
                // Historical blue not yet tracked locally: insert into updated_anticones.
                // This ensures historical blues from the SP chain have their anticone
                // sizes correctly accumulated as new blues are accepted.
                *self.updated_anticones.entry(blue)
                    .or_default() = size + 1;
            }
        }
    }

    /// Returns the selected parent (first blue) if it exists, or None for genesis.
    #[inline]
    pub fn get_selected_parent(&self) -> Option<&Hash> {
        self.mergeset_blues.keys().next()
    }

    /// Remove and return the selected parent hash. Returns None for genesis.
    #[inline]
    pub fn take_selected_parent(mut self) -> Option<Hash> {
        self.mergeset_blues.pop_front().map(|(hash, _)| hash)
    }
}

impl Serializer for MergeSet {
    fn write(&self, writer: &mut Writer) {
        writer.write_u16(self.mergeset_blues.len() as u16);
        for (hash, &size) in &self.mergeset_blues {
            hash.write(writer);
            writer.write_u16(size as u16);
        }

        writer.write_u16(self.updated_anticones.len() as u16);
        for (hash, &size) in &self.updated_anticones {
            hash.write(writer);
            writer.write_u16(size as u16);
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let count = reader.read_u16()? as usize;
        let mut mergeset_blues = LinkedHashMap::with_capacity(count);

        for _ in 0..count {
            let hash = Hash::read(reader)?;
            let size = reader.read_u16()? as usize;
            mergeset_blues.insert(hash.clone(), size);
        }

        let count = reader.read_u16()? as usize;
        let mut updated_anticones = HashMap::with_capacity(count);
        for _ in 0..count {
            let hash = Hash::read(reader)?;
            let size = reader.read_u16()? as usize;
            updated_anticones.insert(hash, size);
        }

        Ok(Self {
            mergeset_blues,
            updated_anticones,
        })
    }
}

#[async_trait]
pub trait MergeSetProvider {
    /// Retrieve the mergeset for a block hash.
    async fn get_mergeset(&self, hash: &Hash) -> Result<MergeSet, BlockchainError>;
}
