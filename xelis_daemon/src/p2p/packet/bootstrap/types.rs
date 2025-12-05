use std::hash::{Hasher, Hash as StdHash};
use indexmap::IndexSet;
use xelis_common::{
    block::TopoHeight,
    contract::ScheduledExecution,
    crypto::Hash,
    difficulty::{CumulativeDifficulty, Difficulty},
    serializer::*,
    varuint::VarUint
};

use crate::core::storage::types::TopoHeightMetadata;

#[derive(Debug)]
pub struct BlockMetadata {
    // Hash of the block
    pub hash: Hash,
    // topoheight metadata
    pub topoheight_metadata: TopoHeightMetadata,
    // Difficulty of the block
    pub difficulty: Difficulty,
    // Cumulative difficulty of the chain
    pub cumulative_difficulty: CumulativeDifficulty,
    // Difficulty P variable
    pub p: VarUint,
    // Block size EMA
    pub size_ema: u32,
    // All transactions marked as executed in this block
    pub executed_transactions: IndexSet<Hash>
}

impl StdHash for BlockMetadata {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.hash.hash(state);
    }
}

impl PartialEq for BlockMetadata {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl Eq for BlockMetadata {}

impl Serializer for BlockMetadata {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let hash = reader.read_hash()?;
        let topoheight_metadata = TopoHeightMetadata::read(reader)?;
        let difficulty = Difficulty::read(reader)?;
        let cumulative_difficulty = CumulativeDifficulty::read(reader)?;
        let p = VarUint::read(reader)?;
        let size_ema = u32::read(reader)?;

        // We don't write it through IndexSet impl directly
        // as we must support any u16 len same as a BlockHeader
        // TODO best would be a const type providing a configurable MAX_ITEMS

        let len = reader.read_u16()?;
        let mut executed_transactions = IndexSet::new();
        for _ in 0..len {
            if !executed_transactions.insert(Hash::read(reader)?) {
                return Err(ReaderError::InvalidValue)
            }
        }

        Ok(Self {
            hash,
            topoheight_metadata,
            difficulty,
            cumulative_difficulty,
            p,
            size_ema,
            executed_transactions
        })
    }

    fn write(&self, writer: &mut Writer) {
        writer.write_hash(&self.hash);
        self.topoheight_metadata.write(writer);
        self.difficulty.write(writer);
        self.cumulative_difficulty.write(writer);
        self.p.write(writer);
        self.size_ema.write(writer);
        self.executed_transactions.write(writer);
    }

    fn size(&self) -> usize {
        self.hash.size()
        + self.topoheight_metadata.size()
        + self.difficulty.size()
        + self.cumulative_difficulty.size()
        + self.p.size()
        + self.executed_transactions.size()
    }
}


#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ScheduledExecutionMetadata {
    pub execution: ScheduledExecution,
    pub execution_topoheight: TopoHeight,
    pub registration_topoheight: TopoHeight
}

impl Serializer for ScheduledExecutionMetadata {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let execution = ScheduledExecution::read(reader)?;
        let execution_topoheight = TopoHeight::read(reader)?;
        let registration_topoheight = TopoHeight::read(reader)?;

        Ok(Self {
            execution,
            execution_topoheight,
            registration_topoheight
        })
    }

    fn write(&self, writer: &mut Writer) {
        self.execution.write(writer);
        self.execution_topoheight.write(writer);
        self.registration_topoheight.write(writer);
    }

    fn size(&self) -> usize {
        self.execution.size()
        + self.execution_topoheight.size()
        + self.registration_topoheight.size()
    }
}