
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    crypto::{Hash, PublicKey},
    serializer::{Error as SerializationError, *},
};

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
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            match self {
                Source::Contract(hash) => {
                    0u8.write(writer)?;
                    hash.write(writer)
                }
                Source::Account(account) => {
                    1u8.write(writer)?;
                    account.write(writer)
                }
                Source::ContractBalance(hash) => {
                    2u8.write(writer)?;
                    hash.write(writer)
                }
                Source::AccountBalance(account) => {
                    3u8.write(writer)?;
                    account.write(writer)
                }
            }
        })
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            let tag = u8::read(reader)?;
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
                tag => Err(SerializationError::new(DecodeError::InvalidValue).context(format!("unknown contract funding source tag {tag}"))),
            }
        })
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