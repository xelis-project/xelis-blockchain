use indexmap::IndexMap;

use crate::{
    contract::Source,
    serializer::*,
};

// Represents an event callback registration
// chunk_id identifies which function chunk to call on the listener contract
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventCallbackRegistration {
    // Chunk ID to invoke on the listener contract
    pub chunk_id: u16,
    // max_gas is the maximum gas that can be used for this callback
    // it is already paid/reserved at the time of registration
    pub max_gas: u64,
    // Sources that paid/reserved the callback gas.
    pub gas_sources: IndexMap<Source, u64>,
}

impl EventCallbackRegistration {
    pub fn new(chunk_id: u16, max_gas: u64, source: Source) -> Self {
        Self {
            chunk_id,
            max_gas,
            gas_sources: [(source, max_gas)].into(),
        }
    }
}

impl Serializer for EventCallbackRegistration {
    fn write(&self, writer: &mut Writer) {
        writer.write_u16(self.chunk_id);
        writer.write_u64(self.max_gas);
        self.gas_sources.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let chunk_id = reader.read_u16()?;
        let max_gas = reader.read_u64()?;
        let gas_sources = IndexMap::read(reader)?;
        Ok(EventCallbackRegistration { chunk_id, max_gas, gas_sources })
    }

    fn size(&self) -> usize {
        self.chunk_id.size() + self.max_gas.size() + self.gas_sources.size()
    }
}