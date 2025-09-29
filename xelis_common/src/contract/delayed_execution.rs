use std::hash;

use serde::{Deserialize, Serialize};
use xelis_vm::ValueCell;

use crate::crypto::Hash;

// Delayed executions are unique per contract
#[derive(Debug, Serialize, Deserialize)]
pub struct DelayedExecution {
    // Contract hash of the module
    pub contract: Hash,
    // Chunk id
    pub chunk_id: u16,
    // Parameters to give for the invoke
    pub params: Vec<ValueCell>,
    // Max gas available to the execution
    // the remaining gas will be paid back to
    // the contract balance
    pub max_gas: u64,
}

impl hash::Hash for DelayedExecution {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.contract.hash(state);
    }
}

pub struct OpaqueDelayedExecution;