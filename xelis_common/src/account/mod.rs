mod balance;
mod nonce;

pub use balance::{VersionedBalance, BalanceRepresentation};
pub use nonce::VersionedNonce;
use xelis_he::CompressedCiphertext;

use crate::serializer::{Reader, ReaderError, Serializer, Writer};

impl Serializer for CompressedCiphertext {
    fn write(&self, writer: &mut Writer) {
        writer.write_bytes(&self.0[0]);
        writer.write_bytes(&self.0[1]);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let left = reader.read_bytes(32)?;
        let right = reader.read_bytes(32)?;
        let compress = CompressedCiphertext([left, right]);
        Ok(compress)
    }
}