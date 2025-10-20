use async_trait::async_trait;
use log::trace;
use xelis_common::{
    block::TopoHeight,
    crypto::Hash,
    serializer::Serializer
};
use crate::core::{
    error::BlockchainError,
    storage::{SledStorage, VersionedScheduledExecutionsProvider}
};

#[async_trait]
impl VersionedScheduledExecutionsProvider for SledStorage {
    async fn delete_scheduled_executions_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete scheduled executions at topoheight {}", topoheight);
        let snapshot = self.snapshot.clone();
        for el in Self::scan_prefix_raw(snapshot.as_ref(), &self.contracts_scheduled_executions_registrations, &topoheight.to_be_bytes()) {
            let (prefixed_key, _) = el?;

            Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.contracts_scheduled_executions_registrations, &prefixed_key)?;

            let (contract, execution_topoheight) = <(Hash, TopoHeight)>::from_bytes(&prefixed_key[8..])?;
            let execution_key = Self::get_contract_scheduled_execution_key(&contract, execution_topoheight);

            Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.contracts_scheduled_executions, &execution_key)?;
        }

        Ok(())
    }

    async fn delete_scheduled_executions_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete scheduled executions above topoheight {}", topoheight);
        let snapshot = self.snapshot.clone();
        for el in Self::iter_raw(snapshot.as_ref(), &self.contracts_scheduled_executions_registrations) {
            let (key, _) = el?;
            let topo = TopoHeight::from_bytes(&key)?;

            if topo > topoheight {
                let (contract, execution_topoheight) = <(Hash, TopoHeight)>::from_bytes(&key[8..])?;
                let execution_key = Self::get_contract_scheduled_execution_key(&contract, execution_topoheight);

                // Delete the "pointer"
                Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.contracts_scheduled_executions_registrations, &key)?;
                // Delete the execution
                Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.contracts_scheduled_executions, &execution_key)?;
            }
        }

        Ok(())
    }

    async fn delete_scheduled_executions_below_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete scheduled executions below topoheight {}", topoheight);
        let snapshot = self.snapshot.clone();
        for el in Self::iter_raw(snapshot.as_ref(), &self.contracts_scheduled_executions_registrations) {
            let (key, _) = el?;
            let topo = TopoHeight::from_bytes(&key)?;

            if topo < topoheight {
                let (contract, execution_topoheight) = <(Hash, TopoHeight)>::from_bytes(&key[8..])?;
                let execution_key = Self::get_contract_scheduled_execution_key(&contract, execution_topoheight);

                // Delete the "pointer"
                Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.contracts_scheduled_executions_registrations, &key)?;
                // Delete the execution
                Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.contracts_scheduled_executions, &execution_key)?;
            }
        }
        Ok(())
    }
}