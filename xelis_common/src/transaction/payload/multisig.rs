use indexmap::IndexSet;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    crypto::elgamal::CompressedPublicKey,
    serializer::{Error as SerializationError, *},
    transaction::MAX_MULTISIG_PARTICIPANTS
};

// MultiSigPayload is a public payload allowing to setup a multi signature account
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct MultiSigPayload {
    // The threshold is the minimum number of signatures required to validate a transaction
    pub threshold: u8,
    // The participants are the public keys that can sign the transaction
    pub participants: IndexSet<CompressedPublicKey>,
}

impl MultiSigPayload {
    // Is the transaction a delete multisig transaction
    pub fn is_delete(&self) -> bool {
        self.threshold == 0 && self.participants.is_empty()
    }
}

impl Serializer for MultiSigPayload {
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            self.threshold.write(writer)?;
            if self.threshold != 0 {
                (self.participants.len() as u8).write(writer)?;
                for participant in &self.participants {
                    participant.write(writer)?;
                }
            }
            Ok(())
        })
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<MultiSigPayload, ReaderError> {
        reader.read_with_context(|reader| {
            let threshold = u8::read(reader)?;
            // Only 0 threshold is allowed for delete multisig
            if threshold == 0 {
                return Ok(MultiSigPayload {
                    threshold,
                    participants: IndexSet::new()
                })
            }

            let participants_len = u8::read(reader)?;
            if participants_len == 0 || participants_len > MAX_MULTISIG_PARTICIPANTS as u8 {
                return Err(SerializationError::new(DecodeError::InvalidSize).context(format!("multisig payload contains {participants_len} participants; expected 1..={MAX_MULTISIG_PARTICIPANTS}")))
            }

            let mut participants = IndexSet::new();
            for _ in 0..participants_len {
                if !participants.insert(CompressedPublicKey::read(reader)?) {
                    return Err(SerializationError::new(DecodeError::InvalidValue).context("duplicate participant public key in multisig payload"))
                }
            }

            Ok(MultiSigPayload {
                threshold,
                participants
            })
        })
    }

    fn size(&self) -> usize {
        1 + 1 + self.participants.iter().map(|p| p.size()).sum::<usize>()
    }
}
