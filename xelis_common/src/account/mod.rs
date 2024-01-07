use serde::{Deserialize, Serialize};

use crate::serializer::{Serializer, ReaderError, Reader, Writer};

#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct VersionedBalance {
    balance: u64,
    previous_topoheight: Option<u64>,
}

impl VersionedBalance {
    pub const fn new(balance: u64, previous_topoheight: Option<u64>) -> Self {
        Self {
            balance,
            previous_topoheight
        }
    }

    pub fn get_balance(&self) -> u64 {
        self.balance
    }

    pub fn set_balance(&mut self, value: u64) {
        self.balance = value;
    }

    pub fn add_balance(&mut self, amount: u64) {
        self.balance += amount;
    }

    pub fn sub_balance(&mut self, amount: u64) {
        self.balance -= amount;
    }

    pub fn get_previous_topoheight(&self) -> Option<u64> {
        self.previous_topoheight        
    }

    pub fn set_previous_topoheight(&mut self, previous_topoheight: Option<u64>) {
        self.previous_topoheight = previous_topoheight;
    }
}

impl Serializer for VersionedBalance {
    fn write(&self, writer: &mut Writer) {
        writer.write_u64(&self.balance);
        if let Some(topo) = &self.previous_topoheight {
            writer.write_u64(topo);
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let balance = reader.read_u64()?;
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