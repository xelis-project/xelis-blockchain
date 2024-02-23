use std::fmt::Display;
use serde::{Deserialize, Serialize};
use xelis_he::{
    CompressedCiphertext,
    DecryptHandle,
    ElGamalCiphertext,
    Identity,
    PedersenCommitment,
    RistrettoPoint
};
use crate::serializer::{Serializer, ReaderError, Reader, Writer};

// Type used in case of future change, to have everything linked to the same type
pub type BalanceRepresentation = CompressedCiphertext;

#[derive(Clone, Deserialize, Serialize)]
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
        ).compress();

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
        write!(f, "Balance[ciphertext[{}, {}], previous: {:?}", hex::encode(self.balance.0[0]), hex::encode(self.balance.0[1]), self.previous_topoheight)
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
        let balance = BalanceRepresentation::read(reader)?;
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

    fn size(&self) -> usize {
        self.balance.size() + if let Some(topoheight) = self.previous_topoheight { topoheight.size() } else { 0 }
    }
}