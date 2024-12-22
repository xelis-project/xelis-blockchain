use log::trace;
use xelis_common::{block::TopoHeight, contract::ContractStorage, crypto::Hash};
use xelis_vm::Constant;
use crate::core::storage::SledStorage;

impl ContractStorage for SledStorage {
    fn load(&mut self, contract: &Hash, key: Constant, topoheight: TopoHeight) -> Result<Option<Constant>, anyhow::Error> {
        trace!("load contract {} key {} data at topoheight {}", contract, key, topoheight);
        Ok(None)
    }

    fn has(&self, contract: &Hash, key: Constant, topoheight: TopoHeight) -> Result<bool, anyhow::Error> {
        trace!("check if contract {} key {} data exists at topoheight {}", contract, key, topoheight);
        Ok(false)
    }
} 