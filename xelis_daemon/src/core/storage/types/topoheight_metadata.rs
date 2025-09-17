use xelis_common::serializer::*;

#[derive(Debug, Clone, Copy)]
pub struct TopoHeightMetadata {
    // block reward
    pub block_reward: u64,
    pub emitted_supply: u64,
    // total fee paid to the miner
    pub total_fees: u64,
    // total fee burned at this topoheight
    pub total_fees_burned: u64,
}

impl Serializer for TopoHeightMetadata {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let rewards = reader.read_u64()?;
        let emitted_supply = reader.read_u64()?;
        let total_fees = reader.read_u64()?;
        let total_fees_burned = reader.read_u64()?;

        Ok(Self {
            block_reward: rewards,
            emitted_supply,
            total_fees,
            total_fees_burned,
        })
    }

    fn write(&self, writer: &mut Writer) {
        self.block_reward.write(writer);
        self.emitted_supply.write(writer);
        self.total_fees.write(writer);
        self.total_fees_burned.write(writer);
    }

    fn size(&self) -> usize {
        self.block_reward.size()
        + self.emitted_supply.size()
        + self.total_fees.size()
        + self.total_fees_burned.size()
    }
}