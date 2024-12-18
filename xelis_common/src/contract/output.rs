use crate::{crypto::{Hash, PublicKey}, serializer::*};

/// Represents the kind of output that a contract can produce
#[derive(Debug, Clone)]
pub enum ContractOutput {
    // Not all the gas got used, refund the remaining gas
    RefundGas {
        /// The amount of gas that is refunded
        amount: u64
    },
    // Transfer some assets to another account
    Transfer {
        /// The amount that is transferred
        amount: u64,
        /// The asset for this output
        asset: Hash,
        /// The destination of the transfer
        destination: PublicKey
    },
    // Exit code returned by the Contract
    // If None, an error occurred
    // If Some(0), the contract executed successfully
    // If Some(n), the contract exited with code n (state not applied!)
    ExitCode(Option<u64>)
}

impl Serializer for ContractOutput {
    fn write(&self, writer: &mut Writer) {
        match self {
            ContractOutput::RefundGas { amount } => {
                writer.write_u8(0);
                amount.write(writer);
            },
            ContractOutput::Transfer { amount, asset, destination } => {
                writer.write_u8(1);
                amount.write(writer);
                asset.write(writer);
                destination.write(writer);
            },
            ContractOutput::ExitCode(code) => {
                writer.write_u8(2);
                code.write(writer);
            }
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        match reader.read_u8()? {
            0 => {
                let amount = u64::read(reader)?;
                Ok(ContractOutput::RefundGas { amount })
            },
            1 => {
                let amount = u64::read(reader)?;
                let asset = Hash::read(reader)?;
                let destination = PublicKey::read(reader)?;
                Ok(ContractOutput::Transfer { amount, asset, destination })
            },
            2 => Ok(ContractOutput::ExitCode(Option::read(reader)?)),
            _ => Err(ReaderError::InvalidValue)
        }
    }
}