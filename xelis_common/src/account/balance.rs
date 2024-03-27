use std::fmt::Display;
use serde::{Deserialize, Serialize};
use crate::crypto::elgamal::{Ciphertext, CompressedCiphertext, DecompressionError};
use crate::serializer::{Serializer, ReaderError, Reader, Writer};

use super::CiphertextCache;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BalanceType {
    // Only incoming funds were added
    // By default, a balance is considered as input
    Input,
    // Only a spending was made from this
    Output,
    // We got both incoming and outgoing funds
    Both
}

impl Serializer for BalanceType {
    fn write(&self, writer: &mut Writer) {
        match self {
            BalanceType::Input => writer.write_u8(0),
            BalanceType::Output => writer.write_u8(1),
            BalanceType::Both => writer.write_u8(2)
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        match reader.read_u8()? {
            0 => Ok(BalanceType::Input),
            1 => Ok(BalanceType::Output),
            2 => Ok(BalanceType::Both),
            _ => Err(ReaderError::InvalidValue)
        }
    }

    fn size(&self) -> usize {
        1
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct VersionedBalance {
    // Output balance is used in case of multi TXs not in same block
    // If you build several TXs at same time but are not in the same block,
    // and a incoming tx happen we need to keep track of the output balance
    output_balance: Option<CiphertextCache>,
    // Final user balance that contains outputs and inputs balance
    // This is the balance shown to a user and used to build TXs
    final_balance: CiphertextCache,
    // Determine if there was any output made in this version
    balance_type: BalanceType,
    // Topoheight of the previous versioned balance
    // If its none, that means it's the first version available
    previous_topoheight: Option<u64>,
}

impl VersionedBalance {
    pub const fn new(final_balance: CiphertextCache, previous_topoheight: Option<u64>) -> Self {
        Self {
            output_balance: None,
            final_balance,
            balance_type: BalanceType::Input,
            previous_topoheight,
        }
    }

    pub fn zero() -> Self {
        let zero = Ciphertext::zero();
        Self::new(CiphertextCache::Decompressed(zero), None)
    }

    pub fn prepare_new(&mut self, previous_topoheight: Option<u64>) {
        self.previous_topoheight = previous_topoheight;
        self.output_balance = None;
        self.balance_type = BalanceType::Input;
    }

    pub fn get_balance(&self) -> &CiphertextCache {
        &self.final_balance
    }

    pub fn get_mut_balance(&mut self) -> &mut CiphertextCache {
        &mut self.final_balance
    }

    pub fn has_output_balance(&self) -> bool {
        self.output_balance.is_some()
    }

    pub fn take_balance_with(self, output: bool) -> CiphertextCache {
        match self.output_balance {
            Some(balance) if output => balance,
            _ => self.final_balance
        }
    }

    pub fn take_balance(self) -> CiphertextCache {
        self.final_balance
    }

    pub fn take_output_balance(self) -> Option<CiphertextCache> {
        self.output_balance
    }

    pub fn set_output_balance(&mut self, value: Option<CiphertextCache>) {
        self.output_balance = value;
    }

    pub fn select_balance(&mut self, output: bool) -> (&mut CiphertextCache, bool) {
        match self.output_balance {
            Some(ref mut balance) if output => (balance, true),
            _ => (&mut self.final_balance, false)
        }
    }

    pub fn set_compressed_balance(&mut self, value: CompressedCiphertext) {
        self.final_balance = CiphertextCache::Compressed(value);
    }

    pub fn set_balance(&mut self, value: CiphertextCache) {
        self.final_balance = value;
    }

    pub fn add_plaintext_to_balance(&mut self, value: u64) -> Result<(), DecompressionError> {
        *self.final_balance.computable()? += value;
        Ok(())
    }

    pub fn get_previous_topoheight(&self) -> Option<u64> {
        self.previous_topoheight        
    }

    pub fn set_previous_topoheight(&mut self, previous_topoheight: Option<u64>) {
        self.previous_topoheight = previous_topoheight;
    }

    pub fn contains_input(&self) -> bool {
        self.balance_type != BalanceType::Output
    }

    pub fn contains_output(&self) -> bool {
        self.balance_type != BalanceType::Input
    }

    pub fn set_balance_type(&mut self, balance_type: BalanceType) {
        self.balance_type = balance_type;
    }

    pub fn consume(self) -> (CiphertextCache, Option<CiphertextCache>, BalanceType, Option<u64>) {
        (self.final_balance, self.output_balance, self.balance_type, self.previous_topoheight)
    }
}

impl Default for VersionedBalance {
    fn default() -> Self {
        Self::zero()
    }
}

impl Display for VersionedBalance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Balance[{}, previous: {:?}", self.final_balance, self.previous_topoheight)
    }
}

impl Serializer for VersionedBalance {
    fn write(&self, writer: &mut Writer) {
        self.final_balance.write(writer);
        self.balance_type.write(writer);
        if let Some(topo) = &self.previous_topoheight {
            writer.write_u64(topo);
        }
        if let Some(output) = &self.output_balance {
            output.write(writer);
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let final_balance = CiphertextCache::read(reader)?;
        let output = BalanceType::read(reader)?;
        let (previous_topoheight, output_balance) = if reader.size() == 0 {
            (None, None)
        } else {
            if reader.size() == 8 {
                (Some(reader.read_u64()?), None)
            } else {
                (Some(reader.read_u64()?), Some(CiphertextCache::read(reader)?))
            }
        };

        Ok(Self {
            output_balance,
            final_balance,
            previous_topoheight,
            balance_type: output
        })
    }

    fn size(&self) -> usize {
        self.final_balance.size()
        + self.balance_type.size()
        + if let Some(topoheight) = self.previous_topoheight { topoheight.size() } else { 0 }
        + if let Some(output_balance) = &self.output_balance { output_balance.size() } else { 0 }
    }
}