use async_trait::async_trait;
use log::trace;
use rocksdb::Direction;
use xelis_common::{block::TopoHeight, serializer::*};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::{Column, ContractId, IteratorMode},
        RocksStorage,
        VersionedScheduledExecutionsProvider
    }
};

#[async_trait]
impl VersionedScheduledExecutionsProvider for RocksStorage {
    async fn delete_scheduled_executions_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete scheduled executions at topoheight {}", topoheight);
        let prefix = topoheight.to_be_bytes();
        self.delete_scheduled_executions_with_mode(IteratorMode::WithPrefix(&prefix, Direction::Forward)).await
    }

    async fn delete_scheduled_executions_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete scheduled executions above topoheight {}", topoheight);
        let start = (topoheight + 1).to_be_bytes();
        self.delete_scheduled_executions_with_mode(IteratorMode::From(&start, Direction::Forward)).await
    }

    async fn delete_scheduled_executions_below_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete scheduled executions below topoheight {}", topoheight);
        let start = topoheight.to_be_bytes();
        self.delete_scheduled_executions_with_mode(IteratorMode::From(&start, Direction::Reverse)).await
    }
}

impl RocksStorage {
    async fn delete_scheduled_executions_with_mode(
        &mut self,
        mode: IteratorMode<'_>,
    ) -> Result<(), BlockchainError> {
        for res in Self::iter_owned_internal::<RawBytes, ()>(&self.db, self.snapshot.as_ref(), mode, Column::DelayedExecutionRegistrations)? {
            let (key, _) = res?;

            // Remove registration entry
            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::DelayedExecutionRegistrations,&key)?;

            // Decode (contract_id, topoheight) from the key and remove corresponding scheduled execution
            let (contract, execution_topoheight) = <(ContractId, TopoHeight)>::from_bytes(&key[8..])?;
            let delayed_key = Self::get_contract_scheduled_execution_key(contract, execution_topoheight);

            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::DelayedExecution, &delayed_key)?;
        }

        Ok(())
    }
}