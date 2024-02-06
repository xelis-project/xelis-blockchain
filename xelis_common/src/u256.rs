use std::{fmt::{self, Display, Formatter}, ops::AddAssign};

use primitive_types::U256;
use serde::{Deserialize, Serialize};

use crate::{difficulty::Difficulty, serializer::{Reader, ReaderError, Serializer, Writer}};

// This is like a variable length integer but only for U256
// It is mostly used to save difficulty and cumulative difficulty on disk
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct CompactU256(U256);

impl CompactU256 {
    pub const fn new(u: U256) -> Self {
        Self(u)
    }

    // This is used to create a CompactU256 with value 0
    pub const fn zero() -> Self {
        Self(U256::zero())
    }

    // This is used to create a CompactU256 with value 1
    pub const fn one() -> Self {
        Self(U256::one())
    }
}

impl Serializer for CompactU256 {
    fn write(&self, writer: &mut Writer) {
        let mut buffer = [0u8; 32];
        self.0.to_big_endian(&mut buffer);
        let mut len = buffer.len();

        // Search how much bytes we need to write
        while len > 0 && buffer[len - 1] == 0 {
            len -= 1;
        }

        writer.write_u8(len as u8);
        writer.write_bytes(&buffer[..len]);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let mut buffer = [0u8; 32];
        let len = reader.read_u8()? as usize;
        let bytes = reader.read_bytes_ref(len)?;
        buffer[0..len].copy_from_slice(bytes);

        Ok(Self(U256::from_big_endian(&buffer)))
    }
}

impl AsRef<U256> for CompactU256 {
    fn as_ref(&self) -> &U256 {
        &self.0
    }
}

impl AsMut<U256> for CompactU256 {
    fn as_mut(&mut self) -> &mut U256 {
        &mut self.0
    }
}

impl From<U256> for CompactU256 {
    fn from(u: U256) -> Self {
        Self(u)
    }
}

impl From<CompactU256> for U256 {
    fn from(c: CompactU256) -> Self {
        c.0
    }
}

impl From<Difficulty> for CompactU256 {
    fn from(difficulty: Difficulty) -> Self {
        U256::from(difficulty).into()
    }
}

impl Display for CompactU256 {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AddAssign for CompactU256 {
    fn add_assign(&mut self, other: Self) {
        self.0 += other.0;
    }
}

mod tests {
    use primitive_types::U256;
    use crate::serializer::{Reader, Serializer};
    use super::CompactU256;

    #[test]
    fn test_serde_0() {
        _test_serde([0u8; 32], 0);
    }

    #[test]
    fn test_serde_highest_byte_u64() {
        let mut bytes = [0u8; 32];
        bytes[7] = 0xFF;
        _test_serde(bytes, 8);
    }

    #[test]
    fn test_serde_low_u128() {
        let mut bytes = [0u8; 32];
        bytes[8] = 1;
        _test_serde(bytes, 9);
    }

    #[test]
    fn test_serde_max() {
        _test_serde([u8::MAX; 32], 32);
    }

    fn _test_serde(bytes: [u8; 32], expected_size: usize) {
        let compact: CompactU256 = U256::from_big_endian(&bytes).into();
        let bytes = compact.to_bytes();
        assert_eq!(bytes.len() - 1, expected_size); // - 1 for byte len
        let compact2 = CompactU256::read(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(compact.as_ref(), compact2.as_ref());
    }
}