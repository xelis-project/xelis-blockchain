use std::fmt::Display;
use serde::{Deserialize, Serialize};
use crate::crypto::elgamal::Ciphertext;
use crate::serializer::{Serializer, ReaderError, Reader, Writer};

use super::CiphertextVariant;

#[derive(Clone, Deserialize, Serialize)]
pub struct VersionedBalance {
    // Output balance is used in case of multi TXs not in same block
    // If you build several TXs at same time but are not in the same block,
    // and a incoming tx happen we need to keep track of the output balance
    output_balance: Option<CiphertextVariant>,
    // Final user balance that contains outputs and inputs balance
    // This is the balance shown to a user and used to build TXs
    final_balance: CiphertextVariant,
    previous_topoheight: Option<u64>,
}

impl VersionedBalance {
    pub const fn new(final_balance: CiphertextVariant, previous_topoheight: Option<u64>) -> Self {
        Self {
            output_balance: None,
            final_balance,
            previous_topoheight
        }
    }

    pub fn zero() -> Self {
        let zero = Ciphertext::zero();

        Self {
            output_balance: None,
            final_balance: CiphertextVariant::Decompressed(zero),
            previous_topoheight: None
        }
    }

    pub fn get_balance(&self) -> &CiphertextVariant {
        &self.final_balance
    }

    pub fn get_mut_balance(&mut self) -> &mut CiphertextVariant {
        &mut self.final_balance
    }

    pub fn take_balance(self) -> CiphertextVariant {
        self.final_balance
    }

    pub fn set_output_balance(&mut self, value: CiphertextVariant) {
        self.output_balance = Some(value);
    }

    pub fn get_output_balance(&self) -> Option<&CiphertextVariant> {
        self.output_balance.as_ref()
    }

    pub fn get_mut_output_balance(&mut self) -> Option<&mut CiphertextVariant> {
        self.output_balance.as_mut()
    }

    pub fn set_balance(&mut self, value: CiphertextVariant) {
        self.final_balance = value;
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

    pub fn consume(self) -> (CiphertextVariant, Option<u64>) {
        (self.final_balance, self.previous_topoheight)
    }
}

impl Default for VersionedBalance {
    fn default() -> Self {
        Self::zero()
    }
}

impl Display for VersionedBalance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Balance[{:?}, previous: {:?}", self.final_balance, self.previous_topoheight)
    }
}

impl Serializer for VersionedBalance {
    fn write(&self, writer: &mut Writer) {
        self.final_balance.write(writer);
        if let Some(topo) = &self.previous_topoheight {
            writer.write_u64(topo);
        }
        if let Some(output) = &self.output_balance {
            output.write(writer);
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let final_balance = CiphertextVariant::read(reader)?;
        let (previous_topoheight, output_balance) = if reader.size() == 0 {
            (None, None)
        } else {
            if reader.size() == 8 {
                (Some(reader.read_u64()?), None)
            } else {
                (Some(reader.read_u64()?), Some(CiphertextVariant::read(reader)?))
            }
        };

        Ok(Self {
            output_balance,
            final_balance,
            previous_topoheight
        })
    }

    fn size(&self) -> usize {
        self.final_balance.size()
        + if let Some(topoheight) = self.previous_topoheight { topoheight.size() } else { 0 }
        + if let Some(output_balance) = &self.output_balance { output_balance.size() } else { 0 }
    }
}