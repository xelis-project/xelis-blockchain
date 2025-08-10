use std::hash;
use indexmap::IndexMap;
use crate::{crypto::Hash, transaction::ContractDeposit};

// TODO: include the contract hash, etc
#[derive(Debug, Clone)]
pub struct ModuleMetadata {
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

impl PartialEq for ModuleMetadata {
    fn eq(&self, other: &Self) -> bool {
        self.contract == other.contract
    }
}

impl Eq for ModuleMetadata {}

impl hash::Hash for ModuleMetadata {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.contract.hash(state);
    }
}