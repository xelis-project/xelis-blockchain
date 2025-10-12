use crate::{
    contract::ScheduledExecutionKind,
    crypto::{Hash, PublicKey},
    serializer::*
};

/// Represents the kind of output that a contract can produce
#[derive(Debug, Clone)]
pub enum ContractLog {
    // Not all the gas got used, refund the remaining gas
    RefundGas {
        /// The amount of gas that is refunded
        amount: u64
    },
    // Transfer some assets to another account
    Transfer {
        contract: Hash,
        /// The amount that is transferred
        amount: u64,
        /// The asset for this output
        asset: Hash,
        /// The destination of the transfer
        destination: PublicKey
    },
    TransferContract {
        // Contract from which its sent
        contract: Hash,
        /// The amount that is transferred
        amount: u64,
        /// The asset for this output
        asset: Hash,
        /// The contract destination of the transfer
        destination: Hash
    },
    // When a contract mint an asset
    Mint {
        // Contract that minted it
        contract: Hash,
        asset: Hash,
        amount: u64
    },
    // When a contract burn an asset
    Burn {
        // Contract that burned it
        contract: Hash,
        asset: Hash,
        amount: u64
    },
    // When a new asset is created
    NewAsset {
        // Contract that created it
        contract: Hash,
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
    // Contract registered a scheduled execution
    ScheduledExecution {
        // Contract hash
        contract: Hash,
        // The hash of the caller
        hash: Hash,
        // at which topoheight it will be called
        kind: ScheduledExecutionKind,
    },
}

impl Serializer for ContractLog {
    fn write(&self, writer: &mut Writer) {
        match self {
            ContractLog::RefundGas { amount } => {
                writer.write_u8(0);
                amount.write(writer);
            },
            ContractLog::Transfer { contract, amount, asset, destination } => {
                writer.write_u8(1);
                contract.write(writer);
                amount.write(writer);
                asset.write(writer);
                destination.write(writer);
            },
            ContractLog::TransferContract { contract, amount, asset, destination } => {
                writer.write_u8(2);
                contract.write(writer);
                amount.write(writer);
                asset.write(writer);
                destination.write(writer);
            },
            ContractLog::Mint { contract, asset, amount } => {
                writer.write_u8(3);
                contract.write(writer);
                asset.write(writer);
                amount.write(writer);
            },
            ContractLog::Burn { contract, asset, amount } => {
                writer.write_u8(4);
                contract.write(writer);
                asset.write(writer);
                amount.write(writer);
            },
            ContractLog::NewAsset { contract, asset } => {
                writer.write_u8(5);
                contract.write(writer);
                asset.write(writer);
            },
            ContractLog::ExitCode(code) => {
                writer.write_u8(6);
                code.write(writer);
            },
            ContractLog::RefundDeposits => {
                writer.write_u8(7);
            },
            ContractLog::GasInjection { contract, amount } => {
                writer.write_u8(8);
                contract.write(writer);
                amount.write(writer);
            },
            ContractLog::ScheduledExecution { contract, hash, kind } => {
                writer.write_u8(9);
                contract.write(writer);
                hash.write(writer);
                kind.write(writer);
            }
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(match reader.read_u8()? {
            0 => {
                let amount = u64::read(reader)?;
                ContractLog::RefundGas { amount }
            },
            1 => {
                let contract = Hash::read(reader)?;
                let amount = u64::read(reader)?;
                let asset = Hash::read(reader)?;
                let destination = PublicKey::read(reader)?;
                ContractLog::Transfer { contract, amount, asset, destination }
            },
            2 => {
                let contract = Hash::read(reader)?;
                let amount = u64::read(reader)?;
                let asset = Hash::read(reader)?;
                let destination = Hash::read(reader)?;
                ContractLog::TransferContract { contract, amount, asset, destination }
            },
            3 => {
                let contract = Hash::read(reader)?;
                let asset = Hash::read(reader)?;
                let amount = u64::read(reader)?;
                ContractLog::Mint { contract, asset, amount }
            },
            4 => {
                let contract = Hash::read(reader)?;
                let asset = Hash::read(reader)?;
                let amount = u64::read(reader)?;
                ContractLog::Burn { contract, asset, amount }
            },
            5 => {
                let contract = Hash::read(reader)?;
                let asset = Hash::read(reader)?;
                ContractLog::NewAsset { contract, asset }
            },
            6 => ContractLog::ExitCode(Option::read(reader)?),
            7 => ContractLog::RefundDeposits,
            8 => ContractLog::GasInjection {
                contract: Hash::read(reader)?,
                amount: u64::read(reader)?
            },
            9 => ContractLog::ScheduledExecution {
                contract: Hash::read(reader)?,
                hash: Hash::read(reader)?,
                kind: ScheduledExecutionKind::read(reader)?,
            },
            _ => return Err(ReaderError::InvalidValue)
        })
    }

    fn size(&self) -> usize {
        1 + match self {
            ContractLog::RefundGas { amount } => amount.size(),
            ContractLog::Transfer { contract, amount, asset, destination } => contract.size() + amount.size() + asset.size() + destination.size(),
            ContractLog::TransferContract { contract, amount, asset, destination } => contract.size() + amount.size() + asset.size() + destination.size(),
            ContractLog::Mint { contract, asset, amount } => contract.size() + asset.size() + amount.size(),
            ContractLog::Burn { contract, asset, amount } => contract.size() + asset.size() + amount.size(),
            ContractLog::NewAsset { contract, asset } => contract.size() + asset.size(),
            ContractLog::ExitCode(code) => code.size(),
            ContractLog::RefundDeposits => 0,
            ContractLog::GasInjection { contract, amount } => contract.size() + amount.size(),
            ContractLog::ScheduledExecution { contract, hash, kind } => contract.size() + hash.size() + kind.size(),
        }
    }
}