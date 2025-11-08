use std::hash;
use indexmap::IndexMap;
use xelis_bytecode::ModuleMetadata as ModuleMetadataInner;
use crate::{crypto::Hash, transaction::ContractDeposit};

pub type ModuleMetadata<'a> = ModuleMetadataInner<'a, ContractMetadata>;

// TODO: include the contract hash, etc
#[derive(Debug, Clone)]
pub struct ContractMetadata {
    // Contract hash of the module invoked
    // This may not be the real module hash,
    // but the hash of the contract that is being executed
    pub contract: Hash,
    // Actual contract caller, if any
    // In case entry point call another contract (no delegation),
    // caller will be set to the contract hash that called this module
    pub caller: Option<Hash>,
    // All deposits made for this module
    pub deposits: IndexMap<Hash, ContractDeposit>,
}

impl PartialEq for ContractMetadata {
    fn eq(&self, other: &Self) -> bool {
        self.contract == other.contract
    }
}

impl Eq for ContractMetadata {}

impl hash::Hash for ContractMetadata {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.contract.hash(state);
    }
}