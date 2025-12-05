use indexmap::IndexSet;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    crypto::elgamal::CompressedPublicKey,
    serializer::*,
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
    fn write(&self, writer: &mut Writer) {
        writer.write_u8(self.threshold);
        if self.threshold != 0 {
            writer.write_u8(self.participants.len() as u8);
            for participant in &self.participants {
                participant.write(writer);
            }
        }
    }

    fn read(reader: &mut Reader) -> Result<MultiSigPayload, ReaderError> {
        let threshold = reader.read_u8()?;
        // Only 0 threshold is allowed for delete multisig
        if threshold == 0 {
            return Ok(MultiSigPayload {
                threshold,
                participants: IndexSet::new()
            })
        }

        let participants_len = reader.read_u8()?;
        if participants_len == 0 || participants_len > MAX_MULTISIG_PARTICIPANTS as u8 {
            return Err(ReaderError::InvalidSize)
        }

        let mut participants = IndexSet::new();
        for _ in 0..participants_len {
            if !participants.insert(CompressedPublicKey::read(reader)?) {
                return Err(ReaderError::InvalidValue)
            }
        }

        Ok(MultiSigPayload {
            threshold,
            participants
        })
    }

    fn size(&self) -> usize {
        1 + 1 + self.participants.iter().map(|p| p.size()).sum::<usize>()
    }
}
