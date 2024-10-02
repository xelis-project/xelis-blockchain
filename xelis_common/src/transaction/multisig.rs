use std::hash::Hash;

use indexmap::IndexSet;
use serde::{Deserialize, Serialize};

use crate::{
    crypto::Signature,
    serializer::{Reader, ReaderError, Serializer, Writer}
};

// SignatureId is a structure that holds the signature and the id of the signer
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignatureId {
    // Signer id
    // This is the index of the signer in the transaction
    id: u8,
    // Signature
    signature: Signature
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
    pub fn add_signature(&mut self, signature: SignatureId) {
        self.signatures.insert(signature);
    }

    // Returns true if the set contains no elements.
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
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

impl Eq for SignatureId {}

impl Serializer for MultiSig {
    fn write(&self, writer: &mut Writer) {
        writer.write_u8(self.signatures.len() as u8);
        for signature in &self.signatures {
            writer.write_u8(signature.id);
            signature.signature.write(writer);
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let len = reader.read_u8()? as usize;
        let mut signatures = IndexSet::new();
        for _ in 0..len {
            let id = reader.read_u8()?;
            let signature = Signature::read(reader)?;
            signatures.insert(SignatureId { id, signature });
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