pub use bulletproofs::RangeProof;

use crate::{
    crypto::elgamal::{
        RISTRETTO_COMPRESSED_SIZE,
        SCALAR_SIZE
    },
    serializer::{
        DecodeError,
        Error as SerializationError,
        Readable,
        Reader,
        ReaderError,
        Serializer,
        Writable,
        Writer,
    },
    transaction::MAX_TRANSFER_COUNT
};


#[allow(non_snake_case)]
impl Serializer for RangeProof {
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            let bytes = self.to_bytes();
            (bytes.len() as u16).write(writer)?;
            writer.extend_bytes(&bytes)
        })
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            let len = u16::read(reader)? as usize;
            // 7 elements in Range Proof: 3 scalars and 4 points
            // 2 scalars in InnerProductProof
            // Each element is 32 bytes
            let min_size = 4 * RISTRETTO_COMPRESSED_SIZE + 5 * SCALAR_SIZE;
            if len % 32 != 0 || len < min_size {
                return Err(SerializationError::new(DecodeError::InvalidSize).context(format!("range proof length {len} must be a multiple of 32 and at least {min_size} bytes")));
            }

            // Those are wrong points
            if (len - min_size) % 32 != 0 {
                return Err(SerializationError::new(DecodeError::InvalidSize).context(format!("range proof payload length after the {min_size}-byte header must be a multiple of 32")));
            }

            // Maximum size of a RangeProof is 2 * MAX_TRANSFER_COUNT * RISTRETTO_COMPRESSED_SIZE
            let max_size_possible = min_size + (MAX_TRANSFER_COUNT * 2).next_power_of_two() * RISTRETTO_COMPRESSED_SIZE;
            if len > max_size_possible {
                return Err(SerializationError::new(DecodeError::InvalidSize).context(format!("range proof length {len} exceeds the maximum of {max_size_possible} bytes")));
            }

            let bytes = reader.read_vec(len)?;
            RangeProof::from_bytes(&bytes).map_err(|error| SerializationError::new(error)
                .context("decoding range proof points and scalars"))
        })
    }

    fn size(&self) -> usize {
        self.to_bytes().len() + 2
    }
}
