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
    pub deposits: IndexMap<Hash, ContractDepositBuilder>,
}

#[cfg(test)]
mod tests {
    use indexmap::indexmap;
    use serde_json::json;
    use xelis_vm::Value;
    use crate::config::XELIS_ASSET;

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

        // println!("{}", serde_json::to_string_pretty(&builder).unwrap());

        let data: InvokeContractBuilder = serde_json::from_value(json!(builder)).unwrap();
        assert_eq!(builder.parameters, data.parameters);
    }
}