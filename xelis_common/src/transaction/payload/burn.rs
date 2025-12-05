use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{crypto::Hash, serializer::*};

// Burn is a public payload allowing to use it as a proof of burn
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct BurnPayload {
    pub asset: Hash,
    pub amount: u64
}

impl Serializer for BurnPayload {
    fn write(&self, writer: &mut Writer) {
        self.asset.write(writer);
        self.amount.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<BurnPayload, ReaderError> {
        let asset = Hash::read(reader)?;
        let amount = reader.read_u64()?;
        Ok(BurnPayload {
            asset,
            amount
        })
    }

    fn size(&self) -> usize {
        self.asset.size() + self.amount.size()
    }
}
