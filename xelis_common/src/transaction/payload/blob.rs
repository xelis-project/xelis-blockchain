use indexmap::IndexSet;
use log::debug;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    crypto::elgamal::{CompressedPublicKey, RISTRETTO_COMPRESSED_SIZE},
    serializer::*,
    transaction::extra_data::UnknownExtraDataFormat
};

// A blob payload, containing an opaque blob of data and a set of destination public keys that should receive it.
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]

pub struct BlobPayload {
    // The blob data, in an unknown format for the verifier.
    pub data: UnknownExtraDataFormat,
    // The set of destination public keys that should be able to decrypt the blob data
    pub destinations: IndexSet<CompressedPublicKey>
}

impl BlobPayload {
    #[inline]
    pub fn get_data(&self) -> &UnknownExtraDataFormat {
        &self.data
    }

    #[inline]
    pub fn get_destinations(&self) -> &IndexSet<CompressedPublicKey> {
        &self.destinations
    }
}

impl Serializer for BlobPayload {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let data = UnknownExtraDataFormat::read(reader)?;
        let len = reader.read_u8()?;
        let mut destinations = IndexSet::new();
        for _ in 0..len {
            let pk = CompressedPublicKey::read(reader)?;
            if !destinations.insert(pk) {
                debug!("Duplicate destination public key in blob payload");
                return Err(ReaderError::InvalidValue);
            }
        }

        Ok(Self { data, destinations })
    }

    fn write(&self, writer: &mut Writer) {
        self.data.write(writer);
        writer.write_u8(self.destinations.len() as u8);
        for pk in &self.destinations {
            pk.write(writer);
        }
    }

    fn size(&self) -> usize {
        self.data.size() + 1 + self.destinations.len() * RISTRETTO_COMPRESSED_SIZE
    }
}