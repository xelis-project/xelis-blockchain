use std::fmt::Display;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use crate::{
    block::TopoHeight,
    crypto::elgamal::{
        Ciphertext,
        CompressedCiphertext,
        DecompressionError
    },
    serializer::{
        Serializer,
        ReaderError,
        Reader,
        Writer
    }
};

use super::CiphertextCache;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
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

impl BalanceType {
    pub fn contains_output(&self) -> bool {
        matches!(self, BalanceType::Output | BalanceType::Both)
    }
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

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq, Debug, JsonSchema)]
pub struct VersionedBalance {
    // Topoheight of the previous versioned balance
    // If its none, that means it's the first version available
    previous_topoheight: Option<TopoHeight>,
    // Output balance is used in case of multi TXs not in same block
    // If you build several TXs at same time but are not in the same block,
    // and a incoming tx happen we need to keep track of the output balance
    output_balance: Option<CiphertextCache>,
    // Final user balance that contains outputs and inputs balance
    // This is the balance shown to a user and used to build TXs
    final_balance: CiphertextCache,
    // Determine if there was any output made in this version
    balance_type: BalanceType,
}

impl VersionedBalance {
    pub const fn new(final_balance: CiphertextCache, previous_topoheight: Option<TopoHeight>) -> Self {
        Self {
            previous_topoheight,
            output_balance: None,
            final_balance,
            balance_type: BalanceType::Input,
        }
    }

    pub fn zero() -> Self {
        let zero = Ciphertext::zero();
        Self::new(CiphertextCache::Decompressed(Some(CompressedCiphertext::zero()), zero), None)
    }

    pub fn prepare_new(&mut self, previous_topoheight: Option<TopoHeight>) {
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

    pub fn get_previous_topoheight(&self) -> Option<TopoHeight> {
        self.previous_topoheight        
    }

    pub fn set_previous_topoheight(&mut self, previous_topoheight: Option<TopoHeight>) {
        self.previous_topoheight = previous_topoheight;
    }

    pub fn contains_input(&self) -> bool {
        self.balance_type != BalanceType::Output
    }

    pub fn contains_output(&self) -> bool {
        self.balance_type.contains_output()
    }

    pub fn set_balance_type(&mut self, balance_type: BalanceType) {
        self.balance_type = balance_type;
    }

    pub fn get_balance_type(&self) -> BalanceType {
        self.balance_type
    }

    pub fn consume(self) -> (CiphertextCache, Option<CiphertextCache>, BalanceType, Option<TopoHeight>) {
        (self.final_balance, self.output_balance, self.balance_type, self.previous_topoheight)
    }

    pub fn as_balance(self, topoheight: TopoHeight) -> Balance {
        Balance {
            topoheight,
            output_balance: self.output_balance,
            final_balance: self.final_balance,
            balance_type: self.balance_type
        }
    
    }
}

#[derive(Debug)]
pub struct Balance {
    // At which topoheight the balance was stored
    pub topoheight: TopoHeight,
    // Output balance if we got some spendings in this version
    pub output_balance: Option<CiphertextCache>,
    // Final user balance that contains outputs and inputs balance
    pub final_balance: CiphertextCache,
    // Determine if there was any output made in this version
    pub balance_type: BalanceType,
}

impl Balance {
    pub fn as_version(self) -> (TopoHeight, VersionedBalance) {
        let version = VersionedBalance {
            output_balance: self.output_balance,
            final_balance: self.final_balance,
            balance_type: self.balance_type,
            previous_topoheight: None
        };
        (self.topoheight, version)
    }
}

impl Serializer for Balance {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let topoheight = TopoHeight::read(reader)?;
        let output_balance = Option::read(reader)?;
        let final_balance = CiphertextCache::read(reader)?;
        let balance_type = BalanceType::read(reader)?;

        Ok(Self {
            topoheight,
            output_balance,
            final_balance,
            balance_type
        })
    }

    fn write(&self, writer: &mut Writer) {
        self.topoheight.write(writer);
        self.output_balance.write(writer);
        self.final_balance.write(writer);
        self.balance_type.write(writer);
    }

    fn size(&self) -> usize {
        self.topoheight.size()
        + self.output_balance.size()
        + self.final_balance.size()
        + self.balance_type.size()
    }
}

#[derive(Debug)]
pub struct AccountSummary {
    // last output balance stored on chain
    // It can be None if the account has no output balance
    // or if the output balance is already in stable_version
    pub output_topoheight: Option<TopoHeight>,
    // last balance stored on chain below or equal to stable topoheight
    pub stable_topoheight: TopoHeight,
}

impl Serializer for AccountSummary {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let output_topoheight = Option::read(reader)?;
        let stable_topoheight = TopoHeight::read(reader)?;

        Ok(Self {
            output_topoheight,
            stable_topoheight
        })
    }

    fn write(&self, writer: &mut Writer) {
        self.output_topoheight.write(writer);
        self.stable_topoheight.write(writer);
    }

    fn size(&self) -> usize {
        self.output_topoheight.size()
        + self.stable_topoheight.size()
    }
}

impl Default for VersionedBalance {
    fn default() -> Self {
        Self::zero()
    }
}

impl Display for VersionedBalance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Balance[{}, previous: {:?}]", self.final_balance, self.previous_topoheight)
    }
}

impl Serializer for VersionedBalance {
    fn write(&self, writer: &mut Writer) {
        self.previous_topoheight.write(writer);
        self.balance_type.write(writer);
        self.final_balance.write(writer);
        self.output_balance.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let previous_topoheight = Option::read(reader)?;
        let balance_type = BalanceType::read(reader)?;
        let final_balance = CiphertextCache::read(reader)?;
        let output_balance = Option::read(reader)?;

        Ok(Self {
            output_balance,
            final_balance,
            previous_topoheight,
            balance_type
        })
    }

    fn size(&self) -> usize {
        self.final_balance.size()
        + self.balance_type.size()
        + self.previous_topoheight.size()
        + self.output_balance.size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_versioned_balance_zero() {
        let mut zero = VersionedBalance::zero();
        zero.set_balance_type(BalanceType::Input);
        let zero_bis = VersionedBalance::from_bytes(&zero.to_bytes()).unwrap();
        assert_eq!(zero, zero_bis);
    }


    #[test]
    fn serde_versioned_balance_previous_topo() {
        let mut zero = VersionedBalance::zero();
        zero.set_balance_type(BalanceType::Input);
        zero.set_previous_topoheight(Some(42));
        let zero_bis = VersionedBalance::from_bytes(&zero.to_bytes()).unwrap();
        assert_eq!(zero, zero_bis);
    }

    #[test]
    fn serde_versioned_balance_output() {
        let mut zero = VersionedBalance::zero();
        zero.set_balance_type(BalanceType::Output);

        let zero_bis = VersionedBalance::from_bytes(&zero.to_bytes()).unwrap();
        assert_eq!(zero, zero_bis);
    }

    #[test]
    fn serde_versioned_balance_both() {
        let mut zero = VersionedBalance::zero();
        zero.set_balance_type(BalanceType::Both);
        zero.set_output_balance(Some(CiphertextCache::Decompressed(None, Ciphertext::zero())));

        let zero_bis = VersionedBalance::from_bytes(&zero.to_bytes()).unwrap();
        assert_eq!(zero, zero_bis);
    }

    #[test]
    fn serde_versioned_balance_output_previous_topo() {
        let mut zero = VersionedBalance::zero();
        zero.set_balance_type(BalanceType::Both);
        zero.set_output_balance(Some(CiphertextCache::Decompressed(None, Ciphertext::zero())));
        zero.set_previous_topoheight(Some(42));

        let zero_bis = VersionedBalance::from_bytes(&zero.to_bytes()).unwrap();
        assert_eq!(zero, zero_bis);
    }
}