mod data;
mod balance;
mod scheduled_execution;

use log::trace;
use async_trait::async_trait;
use xelis_common::{
    block::TopoHeight,
    serializer::{RawBytes, Serializer},
};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::{Column, Contract, ContractId, IteratorMode},
        snapshot::Direction,
        RocksStorage,
        VersionedContractProvider
    }
};

#[async_trait]
impl VersionedContractProvider for RocksStorage {
    // delete versioned contracts at topoheight
    async fn delete_versioned_contracts_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned contracts at topoheight {}", topoheight);
        let prefix = topoheight.to_be_bytes();
        let snapshot = self.snapshot.clone();
        for res in Self::iter_internal::<RawBytes, Option<TopoHeight>>(&self.db, snapshot.as_ref(), IteratorMode::WithPrefix(&prefix, Direction::Forward), Column::VersionedContracts)? {
            let (versioned_key, prev_topo) = res?;

            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedContracts, &versioned_key)?;

            let key_without_prefix = &versioned_key[8..];
            
            let contract_id = ContractId::from_bytes(&key_without_prefix[0..8])?;
            let contract_hash = self.get_contract_from_id(contract_id)?;
            let mut contract = self.get_contract_type(&contract_hash)?;

            if contract.module_pointer.is_some_and(|pointer| pointer >= topoheight) {
                if contract.module_pointer != prev_topo {
                    contract.module_pointer = prev_topo;
                    Self::insert_into_disk_internal(&self.db, self.snapshot.as_mut(), Column::Contracts, &contract_hash, &contract)?;
                }
            }
        }

        Ok(())
    }

    // delete versioned contracts above topoheight
    async fn delete_versioned_contracts_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned contracts above topoheight {}", topoheight);
        let start = (topoheight + 1).to_be_bytes();
        let snapshot = self.snapshot.clone();
        for res in Self::iter_internal::<RawBytes, Option<TopoHeight>>(&self.db, snapshot.as_ref(), IteratorMode::From(&start, Direction::Forward), Column::VersionedContracts)? {
            let (key, prev_topo) = res?;
            // Delete the version we've read
            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedContracts, &key)?;

            let contract_id = ContractId::from_bytes(&key[8..16])?;
            let hash = self.get_contract_from_id(contract_id)?;
            let mut contract = self.get_contract_type(&hash)?;

            // This algorithm should be finding the latest valid data pointer
            // while limiting updates, it will write the highest
            // data pointer if any, or set to None

            // Case 1: pointer is above topoheight => we update it
            // Case 2: pointer is None => we update it
            if contract.module_pointer.is_none_or(|v| v > topoheight) {
                // Case 1: prev topo is below or equal to requested topoheight => update it
                // Case 2: prev topo is None but pointer is Some => we update it
                let filtered = prev_topo.filter(|v| *v <= topoheight);
                if filtered != contract.module_pointer {
                    contract.module_pointer = filtered;
                    Self::insert_into_disk_internal(&self.db, self.snapshot.as_mut(), Column::Contracts, &hash, &contract)?;
                }
            }
        }

        Ok(())
    }

    // delete versioned contracts below topoheight
    async fn delete_versioned_contracts_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        trace!("delete versioned contracts below topoheight {}", topoheight);
        self.delete_versioned_below_topoheight::<Contract, ContractId>(Column::Contracts, Column::VersionedContracts, topoheight, keep_last, |_, v| Ok((v.id, v.module_pointer)))
    }
}