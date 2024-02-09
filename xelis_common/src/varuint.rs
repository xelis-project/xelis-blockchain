use std::{
    fmt::{self, Display, Formatter},
    ops::AddAssign
};
use log::debug;
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use crate::{
    difficulty::Difficulty,
    serializer::{Reader, ReaderError, Serializer, Writer}
};

// This is like a variable length integer but up to U256
// It is mostly used to save difficulty and cumulative difficulty on disk
// In memory, it keeps using U256 (32 bytes)
// On disk it can be as small as 1 byte and as big as 33 bytes
// First byte written is the VarUint length (1 to 32)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct VarUint(U256);

// Support up to 32 bytes for U256
const MAX_VARUINT_SIZE: usize = 32;

impl VarUint {
    // Create a new VarUint from a U256
    pub const fn new(u: U256) -> Self {
        Self(u)
    }

    // Create a VarUint from a u64
    pub const fn from_u64(u: u64) -> Self {
        let buffer = [u, 0, 0, 0];
        Self(U256(buffer))
    }

    // Create a VarUint from a u128
    pub const fn from_u128(u: u128) -> Self {
        let a = (u & 0xFFFF_FFFF_FFFF_FFFF) as u64;
        let b = (u >> 64) as u64;
        let buffer = [a, b, 0, 0];
        Self(U256(buffer))
    }

    // This is used to create a VarUint with value 0
    pub const fn zero() -> Self {
        Self(U256::zero())
    }

    // This is used to create a VarUint with value 1
    pub const fn one() -> Self {
        Self(U256::one())
    }
}

impl Serializer for VarUint {
    fn write(&self, writer: &mut Writer) {
        let mut buffer = [0u8; 32];
        self.0.to_big_endian(&mut buffer);
        let mut len = buffer.len();

        // Search how much bytes we need to write
        while len > 0 && buffer[len - 1] == 0 {
            len -= 1;
        }

        writer.write_u8(len as u8);
        if len > 0 {
            writer.write_bytes(&buffer[..len]);
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let mut buffer = [0u8; 32];
        let len = reader.read_u8()? as usize;

        if len > MAX_VARUINT_SIZE {
            debug!("VarUint size is too big: {}", len);
            return Err(ReaderError::InvalidSize);
        }

        if len == 0 {
            return Ok(Self::zero());
        }

        let bytes = reader.read_bytes_ref(len)?;
        buffer[0..len].copy_from_slice(bytes);

        Ok(Self(U256::from_big_endian(&buffer)))
    }
}

impl AsRef<U256> for VarUint {
    fn as_ref(&self) -> &U256 {
        &self.0
    }
}

impl AsMut<U256> for VarUint {
    fn as_mut(&mut self) -> &mut U256 {
        &mut self.0
    }
}

impl From<U256> for VarUint {
    fn from(u: U256) -> Self {
        Self(u)
    }
}

impl From<VarUint> for U256 {
    fn from(c: VarUint) -> Self {
        c.0
    }
}

impl From<Difficulty> for VarUint {
    fn from(difficulty: Difficulty) -> Self {
        U256::from(difficulty).into()
    }
}

impl Display for VarUint {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AddAssign for VarUint {
    fn add_assign(&mut self, other: Self) {
        self.0 += other.0;
    }
}

mod tests {
    use primitive_types::U256;
    use crate::serializer::{Reader, Serializer};
    use super::VarUint;

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
        let compact: VarUint = U256::from_big_endian(&bytes).into();
        let bytes = compact.to_bytes();
        assert_eq!(bytes.len() - 1, expected_size); // - 1 for byte len
        let compact2 = VarUint::read(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(compact.as_ref(), compact2.as_ref());
    }
}