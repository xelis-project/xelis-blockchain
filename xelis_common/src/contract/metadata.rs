use std::hash;
use indexmap::IndexMap;
use xelis_vm::ModuleMetadata as ModuleMetadataInner;
use crate::{contract::ContractVersion, crypto::Hash, transaction::ContractDeposit};

pub type ModuleMetadata<'a> = ModuleMetadataInner<'a, ContractMetadata>;

// TODO: include the contract hash, etc
#[derive(Debug, Clone)]
pub struct ContractMetadata {
    // Contract hash of the executor 
    // This may not be the real module hash (depending on delegation),
    // but the hash of the contract that is being executed
    pub contract_executor: Hash,
    // Actual contract caller, if any
    // In case a contract calls another contract,
    // caller will be set to the contract hash that called this module
    // Example: Contract A calls Contract B
    // - For Contract A execution, contract_caller is None
    // - For Contract B execution, contract_caller is Some(A's hash)
    // In case of delegation between contracts, this will still be the original caller
    // Example: Contract A delegates to Contract B which calls Contract C
    // - For Contract A execution, contract_caller is None
    // - For Contract B execution, contract_caller is None (as A delegated to B)
    // - For Contract C execution, contract_caller is Some(A's hash)
    pub contract_caller: Option<Hash>,
    // stdlib version of the contract being executed
    pub contract_version: ContractVersion,
    // All deposits made for this contract
    // This is a map of assets to deposit to the called contract
    // Entry point contains the deposits made by the user calling it
    // In case of contract-to-contract calls, deposits are not propagated and may be empty.
    // If during the NEW contract execution some deposits from contract A to contract B are made,
    // they will be recorded here.
    // This allows to easily track (and do) deposits between contracts.
    pub deposits: IndexMap<Hash, ContractDeposit>,
}

impl PartialEq for ContractMetadata {
    fn eq(&self, other: &Self) -> bool {
        self.contract_executor == other.contract_executor
    }
}

impl Eq for ContractMetadata {}

impl hash::Hash for ContractMetadata {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.contract_executor.hash(state);
    }
}