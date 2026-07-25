use std::ops::{Deref, DerefMut};

use xelis_vm::ValueCell;

use crate::{
    contract::{ExitError, ScheduledExecutionKindLog},
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
    // Transfer an asset to another account
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
        kind: ScheduledExecutionKindLog,
    },
    // Payload returned on contract exit
    ExitPayload(ValueCell),
    // Transfer an asset to another account with payload
    TransferPayload {
        contract: Hash,
        /// The amount that is transferred
        amount: u64,
        /// The asset for this output
        asset: Hash,
        /// The destination of the transfer
        destination: PublicKey,
        /// The payload sent with the transfer
        payload: ValueCell,
    },
    // Exit error returned by the Contract
    ExitError(ExitError),
    // Emit event called
    Event {
        // Contract hash
        contract: Hash,
        // Event id
        event_id: u64,
    }
}

/// Serialized contract logs use a u16 count, unlike the generic Vec serializer
/// which limits deserialized vectors to DEFAULT_MAX_ITEMS.
#[derive(Debug, Clone, Default)]
pub struct ContractLogs(pub Vec<ContractLog>);

impl Deref for ContractLogs {
    type Target = Vec<ContractLog>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ContractLogs {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl IntoIterator for ContractLogs {
    type Item = ContractLog;
    type IntoIter = std::vec::IntoIter<ContractLog>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a ContractLogs {
    type Item = &'a ContractLog;
    type IntoIter = std::slice::Iter<'a, ContractLog>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'a> IntoIterator for &'a mut ContractLogs {
    type Item = &'a mut ContractLog;
    type IntoIter = std::slice::IterMut<'a, ContractLog>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut()
    }
}

impl Extend<ContractLog> for ContractLogs {
    fn extend<T: IntoIterator<Item = ContractLog>>(&mut self, iter: T) {
        self.0.extend(iter);
    }
}

impl FromIterator<ContractLog> for ContractLogs {
    fn from_iter<T: IntoIterator<Item = ContractLog>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl From<Vec<ContractLog>> for ContractLogs {
    fn from(logs: Vec<ContractLog>) -> Self {
        Self(logs)
    }
}

impl From<ContractLogs> for Vec<ContractLog> {
    fn from(logs: ContractLogs) -> Self {
        logs.0
    }
}

impl Serializer for ContractLogs {
    fn write(&self, writer: &mut Writer) {
        writer.write_u16(self.0.len() as u16);
        for log in &self.0 {
            log.write(writer);
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let count = reader.read_u16()? as usize;
        let mut logs = Vec::with_capacity(count);
        for _ in 0..count {
            logs.push(ContractLog::read(reader)?);
        }
        Ok(Self(logs))
    }

    fn size(&self) -> usize {
        2 + self.0.iter().map(Serializer::size).sum::<usize>()
    }
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
            },
            ContractLog::ExitPayload(payload) => {
                writer.write_u8(10);
                payload.write(writer);
            },
            ContractLog::TransferPayload { contract, amount, asset, destination, payload } => {
                writer.write_u8(11);
                contract.write(writer);
                amount.write(writer);
                asset.write(writer);
                destination.write(writer);
                payload.write(writer);
            },
            ContractLog::ExitError(err) => {
                writer.write_u8(12);
                err.write(writer);
            },
            ContractLog::Event { contract, event_id } => {
                writer.write_u8(13);
                contract.write(writer);
                event_id.write(writer);
            },
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
                kind: ScheduledExecutionKindLog::read(reader)?,
            },
            10 => {
                let payload = ValueCell::read(reader)?;
                ContractLog::ExitPayload(payload)
            },
            11 => {
                let contract = Hash::read(reader)?;
                let amount = u64::read(reader)?;
                let asset = Hash::read(reader)?;
                let destination = PublicKey::read(reader)?;
                let payload = ValueCell::read(reader)?;
                ContractLog::TransferPayload { contract, amount, asset, destination, payload }
            },
            12 => {
                let err = ExitError::read(reader)?;
                ContractLog::ExitError(err)
            },
            13 => {
                let contract = Hash::read(reader)?;
                let event_id = u64::read(reader)?;
                ContractLog::Event { contract, event_id }
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
            ContractLog::ExitPayload(payload) => payload.size(),
            ContractLog::TransferPayload { contract, amount, asset, destination, payload } => contract.size() + amount.size() + asset.size() + destination.size() + payload.size(),
            ContractLog::ExitError(err) => err.size(),
            ContractLog::Event { contract, event_id } => contract.size() + event_id.size(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_logs_support_more_than_default_vec_limit() {
        let logs = ContractLogs((0..1025).map(|_| ContractLog::RefundDeposits).collect());
        let bytes = logs.to_bytes();
        let decoded = ContractLogs::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.0.len(), 1025);
        assert_eq!(decoded.size(), bytes.len());
    }
}
