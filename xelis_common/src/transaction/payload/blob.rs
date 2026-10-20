use indexmap::IndexSet;
use log::debug;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    crypto::elgamal::{CompressedPublicKey, RISTRETTO_COMPRESSED_SIZE},
    serializer::{Error as SerializationError, *},
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
    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            let data = UnknownExtraDataFormat::read(reader)?;
            let len = reader.read_u8()?;
            let mut destinations = IndexSet::new();
            for _ in 0..len {
                let pk = CompressedPublicKey::read(reader)?;
                if !destinations.insert(pk) {
                    debug!("Duplicate destination public key in blob payload");
                    return Err(SerializationError::new(DecodeError::InvalidValue));
                }
            }

            Ok(Self { data, destinations })
        })
    }

    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            self.data.write(writer)?;
            writer.write_u8(self.destinations.len() as u8)?;
            for pk in &self.destinations {
                pk.write(writer)?;
            }
            Ok(())
        })
    }

    fn size(&self) -> usize {
        self.data.size() + 1 + self.destinations.len() * RISTRETTO_COMPRESSED_SIZE
    }
}