use std::hash::{Hasher, Hash as StdHash};

use indexmap::IndexSet;
use xelis_common::{
    crypto::Hash,
    difficulty::{CumulativeDifficulty, Difficulty},
    varuint::VarUint,
    serializer::*
};


#[derive(Debug)]
pub struct BlockMetadata {
    // Hash of the block
    pub hash: Hash,
    // Emitted supply
    pub supply: u64,
    // Miner reward
    pub reward: u64,
    // Difficulty of the block
    pub difficulty: Difficulty,
    // Cumulative difficulty of the chain
    pub cumulative_difficulty: CumulativeDifficulty,
    // Difficulty P variable
    pub p: VarUint,
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
        let supply = reader.read_u64()?;
        let reward = reader.read_u64()?;
        let difficulty = Difficulty::read(reader)?;
        let cumulative_difficulty = CumulativeDifficulty::read(reader)?;
        let p = VarUint::read(reader)?;

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
            supply,
            reward,
            difficulty,
            cumulative_difficulty,
            p,
            executed_transactions
        })
    }

    fn write(&self, writer: &mut Writer) {
        writer.write_hash(&self.hash);
        writer.write_u64(&self.supply);
        writer.write_u64(&self.reward);
        self.difficulty.write(writer);
        self.cumulative_difficulty.write(writer);
        self.p.write(writer);
        self.executed_transactions.write(writer);
    }

    fn size(&self) -> usize {
        self.hash.size()
        + self.supply.size()
        + self.reward.size()
        + self.difficulty.size()
        + self.cumulative_difficulty.size()
        + self.p.size()
        + self.executed_transactions.size()
    }
}
