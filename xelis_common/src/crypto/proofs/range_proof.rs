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
        ReaderExt,
        Serializer,
        Writable,
        Writer,
        WriterExt,
    },
    transaction::MAX_TRANSFER_COUNT
};


#[allow(non_snake_case)]
impl Serializer for RangeProof {
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            let bytes = self.to_bytes();
            writer.write_u16(bytes.len() as u16)?;
            writer.write_bytes(&bytes)
        })
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            let len = reader.read_u16()? as usize;
            // 7 elements in Range Proof: 3 scalars and 4 points
            // 2 scalars in InnerProductProof
            // Each element is 32 bytes
            let min_size = 4 * RISTRETTO_COMPRESSED_SIZE + 5 * SCALAR_SIZE;
            if len % 32 != 0 || len < min_size {
                return Err(SerializationError::new(DecodeError::InvalidSize));
            }

            // Those are wrong points
            if (len - min_size) % 32 != 0 {
                return Err(SerializationError::new(DecodeError::InvalidSize));
            }

            // Maximum size of a RangeProof is 2 * MAX_TRANSFER_COUNT * RISTRETTO_COMPRESSED_SIZE
            let max_size_possible = min_size + (MAX_TRANSFER_COUNT * 2).next_power_of_two() * RISTRETTO_COMPRESSED_SIZE;
            if len > max_size_possible {
                return Err(SerializationError::new(DecodeError::InvalidSize));
            }

            let bytes = reader.read_vec(len)?;
            RangeProof::from_bytes(&bytes).map_err(SerializationError::new)
        })
    }

    fn size(&self) -> usize {
        self.to_bytes().len() + 2
    }
}
