use std::hash;

use crate::crypto::Hash;

// TODO: include the contract hash, etc
#[derive(Debug, Clone)]
pub struct ModuleMetadata {
    // Contract hash of the module invoked
    pub contract: Hash,
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