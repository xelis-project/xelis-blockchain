
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{crypto::{Hash, PublicKey}, serializer::*};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "type", content = "value")]
pub enum Source {
    // Contract-funded gas used by scheduled executions and runtime injections.
    // For event callbacks created before V7, this also identifies a legacy
    // contract source that was not reserved at registration time.
    Contract(Hash),
    Account(PublicKey),
    // Event callback gas explicitly reserved from a contract balance starting V7.
    ContractBalance(Hash),
    // Future gas explicitly reserved from the original transaction gas pool
    // starting V7. The distinct tag prevents legacy, potentially unbacked
    // account liabilities from being cashed out after the fork.
    AccountBalance(PublicKey),
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
            Source::ContractBalance(hash) => {
                writer.write_u8(2);
                hash.write(writer);
            }
            Source::AccountBalance(account) => {
                writer.write_u8(3);
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
            2 => {
                let hash = Hash::read(reader)?;
                Ok(Source::ContractBalance(hash))
            },
            3 => {
                let account = PublicKey::read(reader)?;
                Ok(Source::AccountBalance(account))
            },
            _ => Err(ReaderError::InvalidValue),
        }
    }

    fn size(&self) -> usize {
        match self {
            Source::Contract(hash) => 1 + hash.size(),
            Source::Account(account) => 1 + account.size(),
            Source::ContractBalance(hash) => 1 + hash.size(),
            Source::AccountBalance(account) => 1 + account.size(),
        }
    }
}