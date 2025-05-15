mod data;
mod balance;
mod supply;

use log::trace;
use async_trait::async_trait;
use rocksdb::Direction;
use xelis_common::{
    block::TopoHeight,
    serializer::{RawBytes, Serializer}, versioned_type::Versioned
};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::{Column, Contract, ContractId, IteratorMode},
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
        for res in Self::iter_owned_internal::<RawBytes, Option<TopoHeight>>(&self.db, self.snapshot.as_ref(), IteratorMode::WithPrefix(&prefix, Direction::Forward), Column::VersionedContracts)? {
            let (versioned_key, prev_topo) = res?;

            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedContracts, &versioned_key)?;

            let key_without_prefix = &versioned_key[8..];
            
            let contract_id = ContractId::from_bytes(&key_without_prefix[0..8])?;
            let contract_hash = self.get_contract_from_id(contract_id)?;
            let mut contract = self.get_contract_type(&contract_hash)?;

            if contract.module_pointer.is_none_or(|pointer| pointer >= topoheight) {
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
        for res in Self::iter_owned_internal::<RawBytes, Option<TopoHeight>>(&self.db, self.snapshot.as_ref(), IteratorMode::From(&start, Direction::Forward), Column::VersionedContracts)? {
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
        let start = topoheight.to_be_bytes();
        if keep_last {
            for res in Self::iter_owned_internal::<(), Contract>(&self.db, self.snapshot.as_ref(), IteratorMode::Start, Column::Contracts)? {
                let (_, contract) = res?;

                if let Some(topo) = contract.module_pointer {
                    // We fetch the last version to take its previous topoheight
                    // And we loop on it to delete them all until the end of the chained data
                    let mut prev_version = Some(topo);
                    // If we are already below the threshold, we can directly erase without patching
                    let mut patched = topo < topoheight;
                    while let Some(prev_topo) = prev_version {
                        let key = Self::get_versioned_contract_key(contract.id, prev_topo);
    
                        // Delete this version from DB if its below the threshold
                        prev_version = self.load_from_disk(Column::VersionedContracts, &key)?;
                        if patched {
                            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedContracts, &key)?;
                        } else {
                            if prev_version.is_some_and(|v| v < topoheight) {
                                trace!("Patching versioned data at topoheight {}", topoheight);
                                patched = true;
                                let mut data: Versioned<RawBytes> = self.load_from_disk(Column::VersionedContracts, &key)?;
                                data.set_previous_topoheight(None);

                                Self::insert_into_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedContracts, &key, &data)?;
                            }
                        }
                    }
                }
            }
        } else {
            for res in Self::iter_owned_internal::<RawBytes, ()>(&self.db, self.snapshot.as_ref(), IteratorMode::From(&start, Direction::Forward), Column::VersionedContracts)? {
                let (key, _) = res?;
                Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedContracts, &key)?;
            }
        }

        Ok(())
    }
}