use xelis_common::serializer::*;

pub struct TopoHeightMetadata {
    pub rewards: u64,
    pub emitted_supply: u64,
    pub burned_supply: u64,
}

impl Serializer for TopoHeightMetadata {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let rewards = reader.read_u64()?;
        let emitted_supply = reader.read_u64()?;
        let burned_supply = reader.read_u64()?;

        Ok(Self {
            rewards,
            emitted_supply,
            burned_supply
        })
    }

    fn write(&self, writer: &mut Writer) {
        self.rewards.write(writer);
        self.emitted_supply.write(writer);
        self.burned_supply.write(writer);
    }

    fn size(&self) -> usize {
        self.rewards.size()
        + self.emitted_supply.size()
        + self.burned_supply.size()
    }
}