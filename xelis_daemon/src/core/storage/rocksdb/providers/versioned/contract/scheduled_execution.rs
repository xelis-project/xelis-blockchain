use async_trait::async_trait;
use log::trace;
use xelis_common::{
    block::TopoHeight,
    contract::ScheduledExecutionKind,
    serializer::{RawBytes, Serializer},
    versioned::Versioned,
};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::{Column, ContractId, IteratorMode},
        snapshot::Direction,
        RocksStorage,
        VersionedScheduledExecutionsProvider,
    }
};

#[async_trait]
impl VersionedScheduledExecutionsProvider for RocksStorage {
    async fn delete_scheduled_executions_at_registration_topoheight(&mut self, registration_topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete scheduled execution versions at registration topoheight {}", registration_topoheight);
        self.run_blocking_mut(|s| {
            let db = s.db.clone();
            let prefix = registration_topoheight.to_be_bytes();
            let snapshot = s.snapshot.clone();
            // Keys start with registration topoheight, so only this topoheight is visited.
            for result in Self::iter_raw_internal(&db, snapshot.as_ref(), IteratorMode::WithPrefix(&prefix, Direction::Forward), Column::VersionedContractScheduledExecutions)? {
                let (key, value) = result?;
                let (_, id) = <(TopoHeight, ContractId)>::from_bytes_non_strict(&key)?;
                // Read only the previous pointer and kind; parameters and gas sources stay encoded.
                let version = Versioned::<ScheduledExecutionKind>::from_bytes_non_strict(&value)?;

                // Rollback removes registrations newest first, so rewind the latest pointer directly.
                let hash = s.get_contract_from_id(id)?;
                let mut contract = s.get_contract_type(&hash)?;
                contract.scheduled_execution_pointer = version.get_previous_topoheight();
                Self::insert_into_disk_internal(&s.db, s.snapshot.as_mut(), Column::Contracts, &hash, &contract)?;

                if let Some(target) = version.get().execution_topoheight() {
                    let index_key = Self::get_scheduled_execution_index_key(id, target);
                    Self::remove_from_disk_internal(&s.db, s.snapshot.as_mut(), Column::ScheduledExecutionIndex, &index_key)?;
                }
                Self::remove_from_disk_internal(&s.db, s.snapshot.as_mut(), Column::VersionedContractScheduledExecutions, &key)?;
            }
            Ok(())
        })
    }

    async fn delete_scheduled_executions_above_registration_topoheight(&mut self, registration_topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete scheduled execution versions above registration topoheight {}", registration_topoheight);
        self.run_blocking_mut(|s| {
            // Start at the next registration topoheight to preserve registrations at the cutoff.
            let start = (registration_topoheight + 1).to_be_bytes();
            let snapshot = s.snapshot.clone();
            for result in Self::iter_raw_internal(&s.db, snapshot.as_ref(), IteratorMode::From(&start, Direction::Forward), Column::VersionedContractScheduledExecutions)? {
                let (key, value) = result?;
                let (_, id) = <(TopoHeight, ContractId)>::from_bytes_non_strict(&key)?;
                let version = Versioned::<ScheduledExecutionKind>::from_bytes_non_strict(&value)?;
                let previous = version.get_previous_topoheight();
                // Only the first removed version per contract links to a surviving registration.
                // Later rows need no contract lookup: their previous registration is also removed.
                if previous.is_none_or(|topoheight| topoheight <= registration_topoheight) {
                    let hash = s.get_contract_from_id(id)?;
                    let mut contract = s.get_contract_type(&hash)?;
                    if contract.scheduled_execution_pointer.is_some_and(|topoheight| topoheight > registration_topoheight) {
                        contract.scheduled_execution_pointer = previous;
                        Self::insert_into_disk_internal(&s.db, s.snapshot.as_mut(), Column::Contracts, &hash, &contract)?;
                    }
                }

                if let Some(target) = version.get().execution_topoheight() {
                    let index_key = Self::get_scheduled_execution_index_key(id, target);
                    Self::remove_from_disk_internal(&s.db, s.snapshot.as_mut(), Column::ScheduledExecutionIndex, &index_key)?;
                }
                Self::remove_from_disk_internal(&s.db, s.snapshot.as_mut(), Column::VersionedContractScheduledExecutions, &key)?;
            }
            Ok(())
        })
    }

    async fn delete_scheduled_executions_below_topoheight(&mut self, execution_topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete scheduled executions below execution topoheight {}", execution_topoheight);
        self.run_blocking_mut(move |s| {
            let db = s.db.clone();
            let end = execution_topoheight.to_be_bytes();
            let snapshot = s.snapshot.clone();
            // The execution index directly identifies expired registrations. The cutoff is exclusive.
            let mode = IteratorMode::Range { lower_bound: None, upper_bound: Some(&end), direction: Direction::Forward };
            for result in Self::iter_raw_internal(&db, snapshot.as_ref(), mode, Column::ScheduledExecutionIndex)? {
                let (key, value) = result?;
                let (_, id) = <(TopoHeight, ContractId)>::from_bytes_non_strict(&key)?;

                let registration = TopoHeight::from_bytes_non_strict(&value)?;
                let version_key = Self::get_versioned_contract_scheduled_execution_key(id, registration);
                let previous = s.load_from_disk::<_, Option<TopoHeight>>(Column::VersionedContractScheduledExecutions, &version_key)?;
                s.unlink_scheduled_execution_registration(id, registration, previous)?;

                // Unlink before deleting either row so remaining versions never point to a missing one.
                Self::remove_from_disk_internal(&s.db, s.snapshot.as_mut(), Column::VersionedContractScheduledExecutions, &version_key)?;
                Self::remove_from_disk_internal(&s.db, s.snapshot.as_mut(), Column::ScheduledExecutionIndex, &key)?;
            }
            Ok(())
        })
    }
}

impl RocksStorage {
    // Registrations form a singly linked history. Removal changes either the contract's
    // latest pointer or the one newer version that points to the removed registration.
    fn unlink_scheduled_execution_registration(&mut self, id: ContractId, registration: TopoHeight, previous: Option<TopoHeight>) -> Result<(), BlockchainError> {
        let hash = self.get_contract_from_id(id)?;
        let mut contract = self.get_contract_type(&hash)?;
        if contract.scheduled_execution_pointer == Some(registration) {
            contract.scheduled_execution_pointer = previous;
            return self.insert_into_disk(Column::Contracts, &hash, &contract);
        }

        // Execution order is independent of registration order, so pruning can remove an interior version.
        // Follow only previous-pointer headers; copy the payload only for the row that needs rewriting.
        let mut current = contract.scheduled_execution_pointer;
        while let Some(topoheight) = current.filter(|topoheight| *topoheight > registration) {
            let key = Self::get_versioned_contract_scheduled_execution_key(id, topoheight);
            current = self.load_from_disk(Column::VersionedContractScheduledExecutions, &key)?;
            if current == Some(registration) {
                let mut successor = self.load_from_disk::<_, Versioned<RawBytes>>(Column::VersionedContractScheduledExecutions, &key)?;
                successor.set_previous_topoheight(previous);
                return self.insert_into_disk(Column::VersionedContractScheduledExecutions, &key, &successor);
            }
        }
        Ok(())
    }
}
