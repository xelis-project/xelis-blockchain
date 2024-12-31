use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use xelis_vm::Constant;
use crate::{
    api::DataElement,
    crypto::{Address, Hash}
};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TransferBuilder {
    pub asset: Hash,
    pub amount: u64,
    pub destination: Address,
    // we can put whatever we want up to EXTRA_DATA_LIMIT_SIZE bytes
    pub extra_data: Option<DataElement>,
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
    pub parameters: Vec<Constant>,
    #[serde(default)]
    pub deposits: IndexMap<Hash, ContractDepositBuilder>,
}

#[cfg(test)]
mod tests {
    use indexmap::indexmap;
    use serde_json::json;
    use xelis_vm::Value;
    use crate::{config::XELIS_ASSET, serializer::Serializer};

    use super::*;

    #[test]
    fn test_invoke_contract_builder() {
        let builder = InvokeContractBuilder {
            contract: XELIS_ASSET,
            max_gas: 1000,
            chunk_id: 0,
            parameters: vec![Constant::Default(Value::U64(100))],
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
    fn test_serde_constant_str() {
        let str_constant = Constant::Default(Value::String("Hello, World!".to_string()));

        // JSON
        let str_data = serde_json::to_string_pretty(&str_constant).unwrap();
        assert_eq!(str_constant, serde_json::from_str::<Constant>(&str_data).unwrap());

        let bytes = str_constant.to_bytes();
        assert_eq!(str_constant, Constant::from_bytes(&bytes).unwrap());
    }
}