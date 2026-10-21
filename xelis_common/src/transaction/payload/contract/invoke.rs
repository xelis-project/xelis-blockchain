use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use xelis_vm::ValueCell;

use crate::{
    contract::InterContractPermission,
    crypto::Hash,
    serializer::{Error as SerializationError, *},
};
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
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            self.contract.write(writer)?;

            self.deposits.write(writer)?;
            self.entry_id.write(writer)?;
            self.max_gas.write(writer)?;

            (self.parameters.len() as u8).write(writer)?;
            for parameter in &self.parameters {
                parameter.write(writer)?;
            }

            self.permission.write(writer)
        })
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<InvokeContractPayload, ReaderError> {
        reader.read_with_context(|reader| {
            let contract = Hash::read(reader)?;
            let deposits = Deposits::read(reader)?;

            let chunk_id = u16::read(reader)?;
            let max_gas = u64::read(reader)?;

            let len = u8::read(reader)? as usize;
            let mut parameters = Vec::with_capacity(len);
            for _ in 0..len {
                parameters.push(ValueCell::read(reader)?);
            }
            let permission = InterContractPermission::read(reader)?;

            Ok(InvokeContractPayload { contract, deposits, entry_id: chunk_id, max_gas, parameters, permission })
        })
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