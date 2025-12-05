use std::ops::{Deref, DerefMut};

use indexmap::IndexMap;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{crypto::Hash, serializer::*};
use super::ContractDeposit;


#[derive(Serialize, Deserialize, Clone, Debug, Default, JsonSchema)]
pub struct Deposits(pub IndexMap<Hash, ContractDeposit>);

impl Deref for Deposits {
    type Target = IndexMap<Hash, ContractDeposit>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Deposits {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Serializer for Deposits {
    fn write(&self, writer: &mut Writer) {
        writer.write_u8(self.0.len() as u8);
        for (key, value) in self.0.iter() {
            key.write(writer);
            value.write(writer);
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let size = reader.read_u8()?;
        let mut deposits = IndexMap::with_capacity(size as usize);
        for _ in 0..size {
            let k = Hash::read(reader)?;
            let v = ContractDeposit::read(reader)?;
            deposits.insert(k, v);
        }

        Ok(Self(deposits))
    }

    fn size(&self) -> usize {
        // 1 is for the deposit byte size
        1 + self.0.iter()
            .map(|(asset, deposit)| asset.size() + deposit.size())
            .sum::<usize>()
    }
}