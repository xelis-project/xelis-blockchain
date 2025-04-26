pub use bulletproofs::RangeProof;

use crate::{
    crypto::elgamal::{
        RISTRETTO_COMPRESSED_SIZE,
        SCALAR_SIZE
    },
    serializer::{
        Reader,
        ReaderError,
        Serializer,
        Writer
    },
    transaction::MAX_TRANSFER_COUNT
};


#[allow(non_snake_case)]
impl Serializer for RangeProof {
    fn write(&self, writer: &mut Writer) {
        let bytes = self.to_bytes();
        writer.write_u16(bytes.len() as u16);
        writer.write_bytes(&bytes);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let len = reader.read_u16()? as usize;
        // 7 elements in Range Proof: 3 scalars and 4 points
        // 2 scalars in InnerProductProof
        // Each element is 32 bytes
        let min_size = 4 * RISTRETTO_COMPRESSED_SIZE + 5 * SCALAR_SIZE;
        if len % 32 != 0 || len < min_size {
            return Err(ReaderError::InvalidSize);
        }

        // Those are wrong points
        if (len - min_size) % 32 != 0 {
            return Err(ReaderError::InvalidSize);
        }

        // Maximum size of a RangeProof is 2 * MAX_TRANSFER_COUNT * RISTRETTO_COMPRESSED_SIZE
        let max_size_possible = min_size + (MAX_TRANSFER_COUNT * 2).next_power_of_two() * RISTRETTO_COMPRESSED_SIZE;
        if len > max_size_possible {
            return Err(ReaderError::InvalidSize);
        }

        let bytes = reader.read_bytes_ref(len)?;
        RangeProof::from_bytes(&bytes).map_err(|_| ReaderError::InvalidValue)
    }

    fn size(&self) -> usize {
        self.to_bytes().len() + 2
    }
}
