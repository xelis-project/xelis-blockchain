use async_trait::async_trait;
use log::trace;
use itertools::Either;
use xelis_common::{
    block::TopoHeight,
    crypto::Hash,
    contract::ScheduledExecutionKind,
    serializer::{RawBytes, Serializer},
    versioned::Versioned
};
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::{
        SledStorage,
        snapshot::{Direction, IteratorMode},
        VersionedScheduledExecutionsProvider
    },
};

#[async_trait]
impl VersionedScheduledExecutionsProvider for SledStorage {
    async fn delete_scheduled_executions_at_registration_topoheight(&mut self, registration_topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete scheduled executions at registration topoheight {}", registration_topoheight);
        let snapshot = self.snapshot.clone();
        // Keys start with registration topoheight, so only this topoheight is visited.
        for result in Self::scan_prefix_raw(snapshot.as_ref(), &self.versioned_contracts_scheduled_executions, &registration_topoheight.to_be_bytes()) {
            let (key, value) = result?;
            let (_, contract) = <(TopoHeight, Hash)>::from_bytes_non_strict(&key)?;
            // Read only the previous pointer and kind; parameters and gas sources stay encoded.
            let version = Versioned::<ScheduledExecutionKind>::from_bytes_non_strict(&value)?;
            // Rollback removes registrations newest first, so rewind the latest pointer directly.
            if let Some(previous) = version.get_previous_topoheight() {
                Self::insert_into_disk(self.snapshot.as_mut(), &self.contract_scheduled_execution_pointers, contract.as_bytes(), &previous.to_be_bytes())?;
            } else {
                Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.contract_scheduled_execution_pointers, contract.as_bytes())?;
            }

            if let Some(target) = version.get().execution_topoheight() {
                let index_key = Self::get_scheduled_execution_index_key(&contract, target);
                Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.scheduled_execution_index, &index_key)?;
            }
            Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.versioned_contracts_scheduled_executions, &key)?;
        }
        Ok(())
    }

    async fn delete_scheduled_executions_above_registration_topoheight(&mut self, registration_topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete scheduled executions above registration topoheight {}", registration_topoheight);
        let snapshot = self.snapshot.clone();
        // Start at the next registration topoheight in both the database and pending snapshot writes.
        let start = (registration_topoheight + 1).to_be_bytes();
        let tree = &self.versioned_contracts_scheduled_executions;
        let entries = tree.range(start..);
        let entries = match snapshot.as_ref() {
            Some(snapshot) => Either::Left(snapshot.lazy_iter_raw(tree.into(), IteratorMode::From(&start, Direction::Forward), entries)),
            None => Either::Right(entries.map(|result| {
                let (key, value) = result?;
                Ok((key.into(), value.into()))
            })),
        };
        for result in entries {
            let (key, value) = result?;
            let (_, contract) = <(TopoHeight, Hash)>::from_bytes_non_strict(&key)?;

            let version = Versioned::<ScheduledExecutionKind>::from_bytes_non_strict(&value)?;
            let previous = version.get_previous_topoheight();
            // Only the first removed version per contract links to a surviving registration.
            // Later rows need no pointer lookup: their previous registration is also removed.
            if previous.is_none_or(|topoheight| topoheight <= registration_topoheight) {
                let pointer = self.load_optional_from_disk::<TopoHeight, _>(&self.contract_scheduled_execution_pointers, contract.as_bytes())?;
                if pointer.is_some_and(|topoheight| topoheight > registration_topoheight) {
                    if let Some(previous) = previous {
                        Self::insert_into_disk(self.snapshot.as_mut(), &self.contract_scheduled_execution_pointers, contract.as_bytes(), &previous.to_be_bytes())?;
                    } else {
                        Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.contract_scheduled_execution_pointers, contract.as_bytes())?;
                    }
                }
            }

            if let Some(target) = version.get().execution_topoheight() {
                let index_key = Self::get_scheduled_execution_index_key(&contract, target);
                Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.scheduled_execution_index, &index_key)?;
            }
            Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.versioned_contracts_scheduled_executions, &key)?;
        }
        Ok(())
    }

    async fn delete_scheduled_executions_below_topoheight(&mut self, execution_topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete scheduled executions below execution topoheight {}", execution_topoheight);
        let snapshot = self.snapshot.clone();
        // Exclude the cutoff in both the database and pending snapshot writes.
        let end = execution_topoheight.to_be_bytes();
        let tree = &self.scheduled_execution_index;
        let entries = tree.range(..end);
        let mode = IteratorMode::Range { lower_bound: None, upper_bound: Some(&end), direction: Direction::Forward };
        let entries = match snapshot.as_ref() {
            Some(snapshot) => Either::Left(snapshot.lazy_iter_raw(tree.into(), mode, entries)),
            None => Either::Right(entries.map(|result| {
                let (key, value) = result?;
                Ok((key.into(), value.into()))
            })),
        };
        for result in entries {
            let (key, value) = result?;
            let (_, contract) = <(TopoHeight, Hash)>::from_bytes_non_strict(&key)?;

            let registration = TopoHeight::from_bytes_non_strict(&value)?;
            let version_key = Self::get_versioned_key(contract.as_bytes(), registration);
            let previous = self.load_from_disk::<Option<TopoHeight>, _>(&self.versioned_contracts_scheduled_executions, &version_key, DiskContext::ScheduledExecution(registration))?;
            self.unlink_scheduled_execution_registration(&contract, registration, previous)?;

            // Unlink before deleting either row so remaining versions never point to a missing one.
            Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.versioned_contracts_scheduled_executions, version_key.as_ref())?;
            Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.scheduled_execution_index, &key)?;
        }
        Ok(())
    }
}

impl SledStorage {
    // Registrations form a singly linked history. Removal changes either the contract's
    // latest pointer or the one newer version that points to the removed registration.
    fn unlink_scheduled_execution_registration(&mut self, contract: &Hash, registration: TopoHeight, previous: Option<TopoHeight>) -> Result<(), BlockchainError> {
        let pointer = self.load_optional_from_disk::<TopoHeight, _>(&self.contract_scheduled_execution_pointers, contract.as_bytes())?;
        if pointer == Some(registration) {
            if let Some(previous) = previous {
                Self::insert_into_disk(self.snapshot.as_mut(), &self.contract_scheduled_execution_pointers, contract.as_bytes(), &previous.to_be_bytes())?;
            } else {
                Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.contract_scheduled_execution_pointers, contract.as_bytes())?;
            }
            return Ok(());
        }

        // Execution order is independent of registration order, so pruning can remove an interior version.
        // Follow only previous-pointer headers; copy the payload only for the row that needs rewriting.
        let mut current = pointer;
        while let Some(topoheight) = current.filter(|topoheight| *topoheight > registration) {
            let key = Self::get_versioned_key(contract.as_bytes(), topoheight);
            current = self.load_from_disk(&self.versioned_contracts_scheduled_executions, &key, DiskContext::ScheduledExecution(topoheight))?;
            if current == Some(registration) {
                let mut successor = self.load_from_disk::<Versioned<RawBytes>, _>(&self.versioned_contracts_scheduled_executions, &key, DiskContext::ScheduledExecution(topoheight))?;
                successor.set_previous_topoheight(previous);
                Self::insert_into_disk(self.snapshot.as_mut(), &self.versioned_contracts_scheduled_executions, &key, successor.to_bytes())?;
                break;
            }
        }
        Ok(())
    }
}