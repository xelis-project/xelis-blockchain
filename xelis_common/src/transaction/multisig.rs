use std::hash::Hash;

use indexmap::IndexSet;
use serde::{Deserialize, Serialize};

use crate::{
    crypto::{elgamal::CompressedPublicKey, Signature},
    serializer::{Reader, ReaderError, Serializer, Writer}
};

use super::MAX_MULTISIG_PARTICIPANTS;

// MultiSigPayload is a public payload allowing to setup a multi signature account
#[derive(Serialize, Deserialize, Clone, Debug)]
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

// SignatureId is a structure that holds the signature and the id of the signer
#[derive(Serialize, Deserialize, Debug, Clone, Eq)]
pub struct SignatureId {
    // Signer id
    // This is the index of the signer in the transaction
    pub id: u8,
    // Signature
    pub signature: Signature
}

// MultiSig is a structure that holds a set of signatures
// that are required to validate a transaction
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MultiSig {
    signatures: IndexSet<SignatureId>,
}

impl MultiSig {
    /// Creates a new MultiSig
    pub fn new() -> Self {
        Self {
            signatures: IndexSet::new(),
        }
    }

    /// Adds a signature to the MultiSig
    /// Returns true if the signature was added
    pub fn add_signature(&mut self, signature: SignatureId) -> bool {
        self.signatures.insert(signature)
    }

    /// Gets the signatures
    pub fn get_signatures(&self) -> &IndexSet<SignatureId> {
        &self.signatures
    }

    /// Returns true if the set contains no elements.
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    /// Returns the number of signatures
    pub fn len(&self) -> usize {
        self.signatures.len()
    }
}

impl Hash for SignatureId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl PartialEq for SignatureId {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Serializer for MultiSig {
    fn write(&self, writer: &mut Writer) {
        writer.write_u8(self.signatures.len() as u8);
        for signature in &self.signatures {
            signature.write(writer);
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let len = reader.read_u8()? as usize;
        let mut signatures = IndexSet::new();
        for _ in 0..len {
            if !signatures.insert(SignatureId::read(reader)?) {
                return Err(ReaderError::InvalidValue);
            }
        }
        Ok(Self { signatures })
    }

    fn size(&self) -> usize {
        let mut size = 1;
        for signature in &self.signatures {
            size += 1 + signature.signature.size();
        }
        size
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

impl Serializer for SignatureId {
    fn write(&self, writer: &mut Writer) {
        writer.write_u8(self.id);
        self.signature.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let id = reader.read_u8()?;
        let signature = Signature::read(reader)?;
        Ok(Self { id, signature })
    }

    fn size(&self) -> usize {
        1 + self.signature.size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multisig_unique_signer_id() {
        let mut multisig = MultiSig::new();
        let mut signature = SignatureId {
            id: 0,
            signature: Signature::from_bytes(&[0; 64]).unwrap(),
        };

        assert!(multisig.add_signature(signature.clone()));
        assert!(!multisig.add_signature(signature.clone()));

        signature.signature = Signature::from_bytes(&[1; 64]).unwrap();
        assert!(!multisig.add_signature(signature.clone()));
    }
}