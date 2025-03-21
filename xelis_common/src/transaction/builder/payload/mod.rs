use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use xelis_vm::ValueCell;
use crate::{
    api::DataElement,
    crypto::{Address, Hash}
};

fn default_bool_true() -> bool {
    true
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TransferBuilder {
    pub asset: Hash,
    pub amount: u64,
    pub destination: Address,
    // we can put whatever we want up to EXTRA_DATA_LIMIT_SIZE bytes
    pub extra_data: Option<DataElement>,
    // Encrypt the extra data by default
    // Set to false if you want to keep it public
    #[serde(default = "default_bool_true")]
    pub encrypt_extra_data: bool
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MultiSigBuilder {
    pub participants: IndexSet<Address>,
    pub threshold: u8,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ContractDepositBuilder {
    pub amount: u64,
    #[serde(default)]
    pub private: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InvokeContractBuilder {
    pub contract: Hash,
    pub max_gas: u64,
    pub chunk_id: u16,
    pub parameters: Vec<ValueCell>,
    #[serde(default)]
    pub deposits: IndexMap<Hash, ContractDepositBuilder>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DeployContractBuilder {
    // Module to deploy
    pub module: String,
    // Inner invoke during the deploy
    pub invoke: Option<DeployContractInvokeBuilder>
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DeployContractInvokeBuilder {
    pub max_gas: u64,
    pub chunk_id: u16,
    pub parameters: Vec<ValueCell>,
    #[serde(default)]
    pub deposits: IndexMap<Hash, ContractDepositBuilder>,
}

#[cfg(test)]
mod tests {
    use indexmap::indexmap;
    use serde_json::json;
    use xelis_vm::Primitive;
    use crate::{config::XELIS_ASSET, serializer::Serializer};

    use super::*;

    #[test]
    fn test_invoke_contract_builder() {
        let builder = InvokeContractBuilder {
            contract: XELIS_ASSET,
            max_gas: 1000,
            chunk_id: 0,
            parameters: vec![ValueCell::Default(Primitive::U64(100))],
            deposits: indexmap! {
                XELIS_ASSET => ContractDepositBuilder {
                    amount: 100,
                    private: false,
                }
            },
        };

        let data: InvokeContractBuilder = serde_json::from_value(json!(builder)).unwrap();
        assert_eq!(builder.parameters, data.parameters);
    }

    #[test]
    fn test_serde_value_cell_str() {
        let str_cell = ValueCell::Default(Primitive::String("Hello, World!".to_string()));

        // JSON
        let str_data = serde_json::to_string_pretty(&str_cell).unwrap();
        assert_eq!(str_cell, serde_json::from_str::<ValueCell>(&str_data).unwrap());

        let bytes = str_cell.to_bytes();
        assert_eq!(str_cell, ValueCell::from_bytes(&bytes).unwrap());
    }
}