use std::fmt::Display;

use serde::{Deserialize, Serialize};
use xelis_he::{
    CompressedCiphertext, DecryptHandle, ElGamalCiphertext, Identity, PedersenCommitment, RistrettoPoint
};

use crate::serializer::{Serializer, ReaderError, Reader, Writer};

// Type used in case of future change, to have everything linked to the same type
pub type BalanceRepresentation = ElGamalCiphertext;

// Initial balance when a new account is created
pub const INITIAL_BALANCE: VersionedBalance = VersionedBalance::new(
    ElGamalCiphertext::new(
        PedersenCommitment::from_point(RistrettoPoint::identity()),
        DecryptHandle::from_point(RistrettoPoint::identity())
    ),
    None
);

#[derive(Clone, Serialize, Deserialize)]
pub struct VersionedBalance {
    #[serde(skip_serialization)]
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

    pub fn get_balance(&self) -> &BalanceRepresentation {
        &self.balance
    }

    pub fn take_balance(self) -> BalanceRepresentation {
        self.balance
    }

    pub fn set_balance(&mut self, value: BalanceRepresentation) {
        self.balance = value;
    }

    pub fn add_plaintext_to_balance(&mut self, value: u64) {
        // self.balance += Scalar::from(value);
    }

    pub fn get_previous_topoheight(&self) -> Option<u64> {
        self.previous_topoheight        
    }

    pub fn set_previous_topoheight(&mut self, previous_topoheight: Option<u64>) {
        self.previous_topoheight = previous_topoheight;
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

#[derive(Clone, Serialize, Deserialize)]
pub struct VersionedNonce {
    nonce: u64,
    previous_topoheight: Option<u64>,
}

impl VersionedNonce {
    pub fn new(nonce: u64, previous_topoheight: Option<u64>) -> Self {
        Self {
            nonce,
            previous_topoheight
        }
    }

    pub fn get_nonce(&self) -> u64 {
        self.nonce
    }

    pub fn set_nonce(&mut self, value: u64) {
        self.nonce = value;
    }

    pub fn get_previous_topoheight(&self) -> Option<u64> {
        self.previous_topoheight        
    }

    pub fn set_previous_topoheight(&mut self, previous_topoheight: Option<u64>) {
        self.previous_topoheight = previous_topoheight;
    }
}

impl Serializer for VersionedNonce {
    fn write(&self, writer: &mut Writer) {
        writer.write_u64(&self.nonce);
        if let Some(topo) = &self.previous_topoheight {
            writer.write_u64(topo);
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let nonce = reader.read_u64()?;
        let previous_topoheight = if reader.size() == 0 {
            None
        } else {
            Some(reader.read_u64()?)
        };

        Ok(Self {
            nonce,
            previous_topoheight
        })
    }
}

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