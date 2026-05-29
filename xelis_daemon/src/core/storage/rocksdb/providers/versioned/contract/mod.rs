mod data;
mod balance;
mod scheduled_execution;
mod event_callback;

use log::trace;
use async_trait::async_trait;
use xelis_common::{
    block::TopoHeight,
    serializer::Serializer,
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
        self.run_blocking_mut(|s| {
            let prefix = topoheight.to_be_bytes();
            let snapshot = s.snapshot.clone();
            for res in Self::iter_raw_internal(&s.db, snapshot.as_ref(), IteratorMode::WithPrefix(&prefix, Direction::Forward), Column::VersionedContracts)? {
                let (versioned_key, value) = res?;

                Self::remove_from_disk_internal(&s.db, s.snapshot.as_mut(), Column::VersionedContracts, &versioned_key)?;

                let key_without_prefix = &versioned_key[8..];
                let contract_id = ContractId::from_bytes(&key_without_prefix[0..8])?;
                let contract_hash = s.get_contract_from_id(contract_id)?;
                let mut contract = s.get_contract_type(&contract_hash)?;

                if contract.module_pointer.is_some_and(|pointer| pointer >= topoheight) {
                    let prev_topo = Option::from_bytes(&value)?;
                    if contract.module_pointer != prev_topo {
                        contract.module_pointer = prev_topo;
                        Self::insert_into_disk_internal(&s.db, s.snapshot.as_mut(), Column::Contracts, &contract_hash, &contract)?;
                    }
                }
            }

            Ok(())
        })
    }

    // delete versioned contracts above topoheight
    async fn delete_versioned_contracts_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned contracts above topoheight {}", topoheight);
        self.run_blocking_mut(|s| {
            let start = (topoheight + 1).to_be_bytes();
            let snapshot = s.snapshot.clone();
            for res in Self::iter_raw_internal(&s.db, snapshot.as_ref(), IteratorMode::From(&start, Direction::Forward), Column::VersionedContracts)? {
                let (key, value) = res?;
                Self::remove_from_disk_internal(&s.db, s.snapshot.as_mut(), Column::VersionedContracts, &key)?;

                let contract_id = ContractId::from_bytes(&key[8..16])?;
                let hash = s.get_contract_from_id(contract_id)?;
                let mut contract = s.get_contract_type(&hash)?;

                if contract.module_pointer.is_none_or(|v| v > topoheight) {
                    let prev_topo = Option::from_bytes(&value)?;
                    let filtered = prev_topo.filter(|v| *v <= topoheight);
                    if filtered != contract.module_pointer {
                        contract.module_pointer = filtered;
                        Self::insert_into_disk_internal(&s.db, s.snapshot.as_mut(), Column::Contracts, &hash, &contract)?;
                    }
                }
            }

            Ok(())
        })
    }

    // delete versioned contracts below topoheight
    async fn delete_versioned_contracts_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        trace!("delete versioned contracts below topoheight {}", topoheight);
        self.delete_versioned_below_topoheight::<ContractId, Contract>(Column::Contracts, Column::VersionedContracts, topoheight, keep_last, |_, v| Ok((v.id, v.module_pointer))).await
    }
}