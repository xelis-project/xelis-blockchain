use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    crypto::Hash,
    serializer::{Error as SerializationError, *},
};

// Burn is a public payload allowing to use it as a proof of burn
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct BurnPayload {
    pub asset: Hash,
    pub amount: u64
}

impl Serializer for BurnPayload {
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            self.asset.write(writer)?;
            self.amount.write(writer)
        })
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<BurnPayload, ReaderError> {
        reader.read_with_context(|reader| {
            let asset = Hash::read(reader)?;
            let amount = u64::read(reader)?;
            Ok(BurnPayload {
                asset,
                amount
            })
        })
    }

    fn size(&self) -> usize {
        self.asset.size() + self.amount.size()
    }
}
