
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{crypto::{Hash, PublicKey}, serializer::*};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "type", content = "value")]
pub enum Source {
    Contract(Hash),
    Account(PublicKey),
}

impl Serializer for Source {
    fn write(&self, writer: &mut Writer) {
        match self {
            Source::Contract(hash) => {
                writer.write_u8(0);
                hash.write(writer);
            }
            Source::Account(account) => {
                writer.write_u8(1);
                account.write(writer);
            }
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let tag = reader.read_u8()?;
        match tag {
            0 => {
                let hash = Hash::read(reader)?;
                Ok(Source::Contract(hash))
            }
            1 => {
                let account = PublicKey::read(reader)?;
                Ok(Source::Account(account))
            },
            _ => Err(ReaderError::InvalidValue),
        }
    }

    fn size(&self) -> usize {
        match self {
            Source::Contract(hash) => 1 + hash.size(),
            Source::Account(account) => 1 + account.size(),
        }
    }
}