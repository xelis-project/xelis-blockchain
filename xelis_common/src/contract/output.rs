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
    TransferContract {
        /// The amount that is transferred
        amount: u64,
        /// The asset for this output
        asset: Hash,
        /// The contract destination of the transfer
        destination: Hash
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
    // When a new asset is created
    NewAsset {
        asset: Hash
    },
    // Exit code returned by the Contract
    // If None, an error occurred
    // If Some(0), the contract executed successfully
    // If Some(n), the contract exited with code n (state not applied!)
    ExitCode(Option<u64>),
    // Inform that we refund the deposits
    RefundDeposits,
    // Increase the gas limit by a contract
    GasInjection {
        contract: Hash,
        amount: u64,
    },
    // Contract registered a delayed execution
    DelayedExecution {
        // Contract hash
        contract: Hash,
        // at which topoheight it will be called
        topoheight: u64,
    }
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
            ContractOutput::TransferContract { amount, asset, destination } => {
                writer.write_u8(2);
                amount.write(writer);
                asset.write(writer);
                destination.write(writer);
            },
            ContractOutput::Mint { asset, amount } => {
                writer.write_u8(3);
                asset.write(writer);
                amount.write(writer);
            },
            ContractOutput::Burn { asset, amount } => {
                writer.write_u8(4);
                asset.write(writer);
                amount.write(writer);
            },
            ContractOutput::NewAsset { asset } => {
                writer.write_u8(5);
                asset.write(writer);
            },
            ContractOutput::ExitCode(code) => {
                writer.write_u8(6);
                code.write(writer);
            },
            ContractOutput::RefundDeposits => {
                writer.write_u8(7);
            },
            ContractOutput::GasInjection { contract, amount } => {
                writer.write_u8(8);
                contract.write(writer);
                amount.write(writer);
            },
            ContractOutput::DelayedExecution { contract, topoheight } => {
                writer.write_u8(9);
                contract.write(writer);
                topoheight.write(writer);
            }
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(match reader.read_u8()? {
            0 => {
                let amount = u64::read(reader)?;
                ContractOutput::RefundGas { amount }
            },
            1 => {
                let amount = u64::read(reader)?;
                let asset = Hash::read(reader)?;
                let destination = PublicKey::read(reader)?;
                ContractOutput::Transfer { amount, asset, destination }
            },
            2 => {
                let amount = u64::read(reader)?;
                let asset = Hash::read(reader)?;
                let destination = Hash::read(reader)?;
                ContractOutput::TransferContract { amount, asset, destination }
            },
            3 => {
                let asset = Hash::read(reader)?;
                let amount = u64::read(reader)?;
                ContractOutput::Mint { asset, amount }
            },
            4 => {
                let asset = Hash::read(reader)?;
                let amount = u64::read(reader)?;
                ContractOutput::Burn { asset, amount }
            },
            5 => {
                let asset = Hash::read(reader)?;
                ContractOutput::NewAsset { asset }
            },
            6 => ContractOutput::ExitCode(Option::read(reader)?),
            7 => ContractOutput::RefundDeposits,
            8 => ContractOutput::GasInjection {
                contract: Hash::read(reader)?,
                amount: u64::read(reader)?
            },
            9 => ContractOutput::DelayedExecution {
                contract: Hash::read(reader)?,
                topoheight: u64::read(reader)?,
            },
            _ => return Err(ReaderError::InvalidValue)
        })
    }

    fn size(&self) -> usize {
        1 + match self {
            ContractOutput::RefundGas { amount } => amount.size(),
            ContractOutput::Transfer { amount, asset, destination } => amount.size() + asset.size() + destination.size(),
            ContractOutput::TransferContract { amount, asset, destination } => amount.size() + asset.size() + destination.size(),
            ContractOutput::Mint { asset, amount } => asset.size() + amount.size(),
            ContractOutput::Burn { asset, amount } => asset.size() + amount.size(),
            ContractOutput::NewAsset { asset } => asset.size(),
            ContractOutput::ExitCode(code) => code.size(),
            ContractOutput::RefundDeposits => 0,
            ContractOutput::GasInjection { contract, amount } => contract.size() + amount.size(),
            ContractOutput::DelayedExecution { contract, topoheight } => contract.size() + topoheight.size(),
        }
    }
}