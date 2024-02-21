use std::fmt::Display;

use serde::{Deserialize, Serialize};
use xelis_he::{
    DecryptHandle, ElGamalCiphertext, Identity, PedersenCommitment, RistrettoPoint
};

use crate::serializer::{Serializer, ReaderError, Reader, Writer};

// Type used in case of future change, to have everything linked to the same type
pub type BalanceRepresentation = ElGamalCiphertext;

#[derive(Clone)]
pub struct VersionedBalance {
    balance: BalanceRepresentation,
    previous_topoheight: Option<u64>,
}

impl VersionedBalance {
    pub const fn new(balance: BalanceRepresentation, previous_topoheight: Option<u64>) -> Self {
        Self {
            balance,
            previous_topoheight
        }
    }

    pub fn zero() -> Self {
        let zero = ElGamalCiphertext::new(
            PedersenCommitment::from_point(RistrettoPoint::identity()),
            DecryptHandle::from_point(RistrettoPoint::identity())
        );

        Self {
            balance: zero,
            previous_topoheight: None
        }
    }

    pub fn get_balance(&self) -> &BalanceRepresentation {
        &self.balance
    }

    pub fn take_balance(self) -> BalanceRepresentation {
        self.balance
    }

    pub fn set_balance(&mut self, value: BalanceRepresentation) {
        self.balance = value;
    }

    pub fn add_plaintext_to_balance(&mut self, _value: u64) {
        // self.balance + Scalar::from(value); 
    }

    pub fn get_previous_topoheight(&self) -> Option<u64> {
        self.previous_topoheight        
    }

    pub fn set_previous_topoheight(&mut self, previous_topoheight: Option<u64>) {
        self.previous_topoheight = previous_topoheight;
    }
}

impl Default for VersionedBalance {
    fn default() -> Self {
        Self::zero()
    }
}

impl Display for VersionedBalance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let handle = self.balance.handle();
        write!(f, "Balance[handle: {:?}, previous: {:?}", handle.as_point(), self.previous_topoheight)
    }
}

impl Serializer for VersionedBalance {
    fn write(&self, writer: &mut Writer) {
        self.balance.write(writer);
        if let Some(topo) = &self.previous_topoheight {
            writer.write_u64(topo);
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let balance = ElGamalCiphertext::read(reader)?;
        let previous_topoheight = if reader.size() == 0 {
            None
        } else {
            Some(reader.read_u64()?)
        };

        Ok(Self {
            balance,
            previous_topoheight
        })
    }
}

impl Serialize for VersionedBalance {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut writer = Writer::new();
        self.write(&mut writer);
        let bytes = writer.bytes();
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for VersionedBalance {
    fn deserialize<D>(deserializer: D) -> Result<VersionedBalance, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let mut reader = Reader::new(&bytes);
        VersionedBalance::read(&mut reader).map_err(serde::de::Error::custom)
    }
}