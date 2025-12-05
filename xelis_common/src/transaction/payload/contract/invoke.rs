use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use xelis_vm::ValueCell;

use crate::{contract::InterContractPermission, crypto::Hash, serializer::*};
use super::Deposits;

// InvokeContractPayload is a public payload allowing to call a smart contract
// It contains all the assets deposited in the contract and the parameters to call the contract
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct InvokeContractPayload {
    // The contract address
    // Contract are the TXID of the transaction that deployed the contract
    pub contract: Hash,
    // Assets deposited with this call
    pub deposits: Deposits,
    // The chunk to invoke
    // It can only be a entry id
    pub entry_id: u16,
    // Additionnal fees to pay
    // This is the maximum of gas that can be used by the contract
    // If a contract uses more gas than this value, the transaction
    // is still accepted by nodes but the contract execution is stopped
    pub max_gas: u64,
    // The parameters to call the contract
    pub parameters: Vec<ValueCell>,
    // The permission of this contract call
    // It is used to restrict access to certain inter-contracts.
    #[serde(default)]
    pub permission: InterContractPermission,
}

impl Serializer for InvokeContractPayload {
    fn write(&self, writer: &mut Writer) {
        self.contract.write(writer);

        self.deposits.write(writer);
        self.entry_id.write(writer);
        self.max_gas.write(writer);

        writer.write_u8(self.parameters.len() as u8);
        for parameter in &self.parameters {
            parameter.write(writer);
        }

        self.permission.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<InvokeContractPayload, ReaderError> {
        let contract = Hash::read(reader)?;
        let deposits = Deposits::read(reader)?;

        let chunk_id = reader.read_u16()?;
        let max_gas = reader.read_u64()?;

        let len = reader.read_u8()? as usize;
        let mut parameters = Vec::with_capacity(len);
        for _ in 0..len {
            parameters.push(ValueCell::read(reader)?);
        }
        let permission = InterContractPermission::read(reader)?;

        Ok(InvokeContractPayload { contract, deposits, entry_id: chunk_id, max_gas, parameters, permission })
    }

    fn size(&self) -> usize {
        let mut size = self.contract.size()
            + self.entry_id.size()
            + self.max_gas.size()
            + self.deposits.size();

        size += 1;
        for parameter in &self.parameters {
            size += parameter.size();
        }
        size += self.permission.size();

        size
    }
}