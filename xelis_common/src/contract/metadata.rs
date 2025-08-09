use crate::crypto::Hash;

// TODO: include the contract hash, etc
#[derive(Debug, Clone)]
pub struct ModuleMetadata {
    // Contract hash of the module invoked
    pub contract: Hash,
}