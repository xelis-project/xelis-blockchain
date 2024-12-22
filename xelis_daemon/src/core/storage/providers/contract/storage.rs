use xelis_common::{contract::ContractStorage, crypto::Hash};
use xelis_vm::Constant;

use crate::core::storage::SledStorage;

impl ContractStorage for SledStorage {
    fn load(&mut self, contract: &Hash, key: Constant) -> Result<Option<Constant>, anyhow::Error> {
        unimplemented!()
    }

    fn has(&self, contract: &Hash, key: Constant) -> Result<bool, anyhow::Error> {
        unimplemented!()
    }

    fn store(&mut self, contract: &Hash, key: Constant, value: Constant) -> Result<(), anyhow::Error> {
        unimplemented!()
    }

    fn delete(&mut self, contract: &Hash, key: Constant) -> Result<(), anyhow::Error> {
        unimplemented!()
    }
} 