use async_trait::async_trait;
use log::trace;
use rocksdb::Direction;
use xelis_common::{block::TopoHeight, serializer::RawBytes};
use crate::core::{error::BlockchainError, storage::{rocksdb::{Column, IteratorMode}, RocksStorage, VersionedDelayedExecutionsProvider}};

#[async_trait]
impl VersionedDelayedExecutionsProvider for RocksStorage {
    async fn delete_delayed_executions_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete delayed executions at topoheight {}", topoheight);
        let prefix = topoheight.to_be_bytes();
        for res in Self::iter_owned_internal::<RawBytes, ()>(&self.db, self.snapshot.as_ref(), IteratorMode::WithPrefix(&prefix, Direction::Forward), Column::DelayedExecution)? {
            let (key, _) = res?;

            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::DelayedExecution, &key)?;
        }

        Ok(())
    }

    async fn delete_delayed_executions_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete delayed executions above topoheight {}", topoheight);
        let start = (topoheight + 1).to_be_bytes();
        for res in Self::iter_owned_internal::<RawBytes, ()>(&self.db, self.snapshot.as_ref(), IteratorMode::From(&start, Direction::Forward), Column::DelayedExecution)? {
            let (key, _) = res?;

            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::DelayedExecution, &key)?;
        }

        Ok(())
    }

    async fn delete_delayed_executions_below_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete delayed executions below topoheight {}", topoheight);
        self.delete_versioned_data_below_topoheight(Column::DelayedExecution, topoheight)
    }
}