use xelis_common::{difficulty::{CumulativeDifficulty, Difficulty}, serializer::*, varuint::VarUint};

// All needed difficulty for a block
pub struct BlockDifficulty {
    pub difficulty: Difficulty,
    pub cumulative_difficulty: CumulativeDifficulty,
    pub covariance: VarUint
}

impl Serializer for BlockDifficulty {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let difficulty = Difficulty::read(reader)?;
        let cumulative_difficulty = CumulativeDifficulty::read(reader)?;
        let covariance = VarUint::read(reader)?;

        Ok(Self {
            difficulty,
            cumulative_difficulty,
            covariance
        })
    }

    fn write(&self, writer: &mut Writer) {
        self.difficulty.write(writer);
        self.cumulative_difficulty.write(writer);
        self.covariance.write(writer);
    }

    fn size(&self) -> usize {
        self.difficulty.size()
        + self.cumulative_difficulty.size()
        + self.covariance.size()
    }
}