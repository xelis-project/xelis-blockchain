use xelis_common::{difficulty::{CumulativeDifficulty, Difficulty}, serializer::*, varuint::VarUint};

// All needed difficulty for a block
pub struct BlockMetadata {
    pub difficulty: Difficulty,
    pub cumulative_difficulty: CumulativeDifficulty,
    pub covariance: VarUint,
    pub size_ema: u32,
}

impl Serializer for BlockMetadata {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let difficulty = Difficulty::read(reader)?;
        let cumulative_difficulty = CumulativeDifficulty::read(reader)?;
        let covariance = VarUint::read(reader)?;
        let size_ema = u32::read(reader)?;

        Ok(Self {
            difficulty,
            cumulative_difficulty,
            covariance,
            size_ema,
        })
    }

    fn write(&self, writer: &mut Writer) {
        self.difficulty.write(writer);
        self.cumulative_difficulty.write(writer);
        self.covariance.write(writer);
        self.size_ema.write(writer);
    }

    fn size(&self) -> usize {
        self.difficulty.size()
        + self.cumulative_difficulty.size()
        + self.covariance.size()
        + self.size_ema.size()
    }
}