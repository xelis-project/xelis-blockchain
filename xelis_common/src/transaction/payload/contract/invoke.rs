use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use xelis_vm::ValueCell;

use crate::{crypto::Hash, serializer::*};
use super::ContractDeposit;

// InvokeContractPayload is a public payload allowing to call a smart contract
// It contains all the assets deposited in the contract and the parameters to call the contract
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InvokeContractPayload {
    // The contract address
    // Contract are the TXID of the transaction that deployed the contract
    pub contract: Hash,
    // Assets deposited with this call
    pub deposits: IndexMap<Hash, ContractDeposit>,
    // The chunk to invoke
    pub chunk_id: u16,
    // Additionnal fees to pay
    // This is the maximum of gas that can be used by the contract
    // If a contract uses more gas than this value, the transaction
    // is still accepted by nodes but the contract execution is stopped
    pub max_gas: u64,
    // The parameters to call the contract
    pub parameters: Vec<ValueCell>
}

impl Serializer for InvokeContractPayload {
    fn write(&self, writer: &mut Writer) {
        self.contract.write(writer);

        writer.write_u8(self.deposits.len() as u8);
        for (asset, deposit) in &self.deposits {
            asset.write(writer);
            deposit.write(writer);
        }

        writer.write_u16(self.chunk_id);
        self.max_gas.write(writer);

        writer.write_u8(self.parameters.len() as u8);
        for parameter in &self.parameters {
            parameter.write(writer);
        }
    }

    fn read(reader: &mut Reader) -> Result<InvokeContractPayload, ReaderError> {
        let contract = Hash::read(reader)?;

        let len = reader.read_u8()? as usize;
        let mut deposits = IndexMap::new();
        for _ in 0..len {
            let asset = Hash::read(reader)?;
            let deposit = ContractDeposit::read(reader)?;
            deposits.insert(asset, deposit);
        }

        let chunk_id = reader.read_u16()?;
        let max_gas = reader.read_u64()?;

        let len = reader.read_u8()? as usize;
        let mut parameters = Vec::with_capacity(len);
        for _ in 0..len {
            parameters.push(ValueCell::read(reader)?);
        }
        Ok(InvokeContractPayload { contract, deposits, chunk_id, max_gas, parameters })
    }

    fn size(&self) -> usize {
        let mut size = self.contract.size()
            + self.chunk_id.size()
            + self.max_gas.size()
        // 1 byte for the deposits length
            + 1;

        for (asset, deposit) in &self.deposits {
            size += asset.size() + deposit.size();
        }

        size += 1;
        for parameter in &self.parameters {
            size += parameter.size();
        }
        size
    }
}