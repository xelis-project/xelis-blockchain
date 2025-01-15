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
    // When a contract mint an asset
    Mint {
        asset: Hash,
        amount: u64
    },
    // When a contract burn an asset
    Burn {
        asset: Hash,
        amount: u64
    },
    // Exit code returned by the Contract
    // If None, an error occurred
    // If Some(0), the contract executed successfully
    // If Some(n), the contract exited with code n (state not applied!)
    ExitCode(Option<u64>),
    // Inform that we refund the deposits
    RefundDeposits
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
            ContractOutput::Mint { asset, amount } => {
                writer.write_u8(2);
                asset.write(writer);
                amount.write(writer);
            },
            ContractOutput::Burn { asset, amount } => {
                writer.write_u8(3);
                asset.write(writer);
                amount.write(writer);
            },
            ContractOutput::ExitCode(code) => {
                writer.write_u8(4);
                code.write(writer);
            },
            ContractOutput::RefundDeposits => {
                writer.write_u8(5);
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
            2 => {
                let asset = Hash::read(reader)?;
                let amount = u64::read(reader)?;
                Ok(ContractOutput::Mint { asset, amount })
            },
            3 => {
                let asset = Hash::read(reader)?;
                let amount = u64::read(reader)?;
                Ok(ContractOutput::Burn { asset, amount })
            },
            4 => Ok(ContractOutput::ExitCode(Option::read(reader)?)),
            5 => Ok(ContractOutput::RefundDeposits),
            _ => Err(ReaderError::InvalidValue)
        }
    }

    fn size(&self) -> usize {
        match self {
            ContractOutput::RefundGas { amount } => 1 + amount.size(),
            ContractOutput::Transfer { amount, asset, destination } => 1 + amount.size() + asset.size() + destination.size(),
            ContractOutput::Mint { asset, amount } => 1 + asset.size() + amount.size(),
            ContractOutput::Burn { asset, amount } => 1 + asset.size() + amount.size(),
            ContractOutput::ExitCode(code) => 1 + code.size(),
            ContractOutput::RefundDeposits => 1
        }
    }
}