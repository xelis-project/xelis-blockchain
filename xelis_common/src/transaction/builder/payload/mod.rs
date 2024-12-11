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