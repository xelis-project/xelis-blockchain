use log::trace;
use xelis_common::{block::TopoHeight, contract::ContractStorage, crypto::Hash};
use xelis_vm::Constant;
use crate::core::storage::{ContractDataProvider, SledStorage};

impl ContractStorage for SledStorage {
    fn load(&self, contract: &Hash, key: &Constant, topoheight: TopoHeight) -> Result<Option<(TopoHeight, Option<Constant>)>, anyhow::Error> {
        trace!("load contract {} key {} data at topoheight {}", contract, key, topoheight);
        let res = futures::executor::block_on(self.get_contract_data_at_maximum_topoheight_for(contract, &key, topoheight))?;

        match res {
            Some((topoheight, data)) => match data.take() {
                Some(data) => Ok(Some((topoheight, Some(data)))),
                None => Ok(Some((topoheight, None))),
            },
            None => Ok(None),
        }
    }

    fn has(&self, contract: &Hash, key: &Constant, topoheight: TopoHeight) -> Result<bool, anyhow::Error> {
        trace!("check if contract {} key {} data exists at topoheight {}", contract, key, topoheight);
        let contains = futures::executor::block_on(self.has_contract_data_at_topoheight(contract, &key, topoheight))?;
        Ok(contains)
    }

    fn load_latest_topoheight(&self, contract: &Hash, key: &Constant, topoheight: TopoHeight) -> Result<Option<TopoHeight>, anyhow::Error> {
        trace!("load latest topoheight for contract {} key {} at topoheight {}", contract, key, topoheight);
        let res = futures::executor::block_on(self.get_contract_data_topoheight_at_maximum_topoheight_for(contract, &key, topoheight))?;
        Ok(res)
    }
}