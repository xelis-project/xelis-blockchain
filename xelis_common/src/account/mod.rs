mod balance;
mod nonce;

pub use balance::{VersionedBalance, BalanceRepresentation};
pub use nonce::VersionedNonce;
use xelis_he::{CompressedCiphertext, ElGamalCiphertext};

use crate::serializer::{Reader, ReaderError, Serializer, Writer};

impl Serializer for ElGamalCiphertext {
    fn write(&self, writer: &mut Writer) {
        let compress = self.compress();
        writer.write_bytes(&compress.0[0]);
        writer.write_bytes(&compress.0[1]);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let left = reader.read_bytes(32)?;
        let right = reader.read_bytes(32)?;
        let compress = CompressedCiphertext([left, right]);

        Ok(compress.decompress().map_err(|e| ReaderError::Any(e.into()))?)
    }
}