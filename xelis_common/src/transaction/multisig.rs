use std::hash::Hash;

use indexmap::IndexSet;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    crypto::Signature,
    serializer::{Reader, ReaderError, Serializer, Writer}
};

// SignatureId is a structure that holds the signature and the id of the signer
#[derive(Serialize, Deserialize, Debug, Clone, Eq, JsonSchema)]
pub struct SignatureId {
    // Signer id
    // This is the index of the signer in the transaction
    pub id: u8,
    // Signature
    pub signature: Signature
}

// MultiSig is a structure that holds a set of signatures
// that are required to validate a transaction
#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
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