use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use xelis_vm::OwnedValue;

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
    pub parameters: Vec<OwnedValue>,
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
                parameters.push(OwnedValue::read(reader)?);
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

#[cfg(test)]
mod tests {
    use crate::transaction::Transaction;
    use super::*;

    #[test]
    fn owned_parameters_roundtrip_and_clone_independently() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<InvokeContractPayload>();
        assert_send_sync::<Transaction>();

        let payload = InvokeContractPayload {
            contract: Hash::zero(),
            deposits: Deposits::default(),
            entry_id: 7,
            max_gas: 1000,
            parameters: vec![OwnedValue::Object(vec![OwnedValue::Map([
                (OwnedValue::from("key".to_owned()), OwnedValue::Bytes(vec![1, 2, 3])),
            ].into_iter().collect())])],
            permission: InterContractPermission::All,
        };
        let bytes = payload.to_bytes().unwrap();
        assert_eq!(bytes.len(), payload.size());
        let decoded = InvokeContractPayload::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.parameters, payload.parameters);
        assert_eq!(decoded.to_bytes().unwrap(), bytes);
        let json = serde_json::to_vec(&payload).unwrap();
        let decoded: InvokeContractPayload = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.parameters, payload.parameters);

        let mut cloned = payload.clone();
        cloned.parameters[0].as_mut_vec().unwrap()[0].as_mut_map().unwrap().clear();
        assert_eq!(payload.to_bytes().unwrap(), bytes);
        assert_ne!(cloned.parameters, payload.parameters);
    }

    #[test]
    fn owned_values_preserve_primitive_wire_tags() {
        assert_eq!(OwnedValue::from(42u8).to_bytes().unwrap(), vec![0, 1, 42]);
        assert_eq!(OwnedValue::from(true).to_bytes().unwrap(), vec![0, 7, 1]);
    }
}
