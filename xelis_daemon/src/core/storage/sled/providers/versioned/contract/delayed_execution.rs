use async_trait::async_trait;
use log::trace;
use xelis_common::{
    serializer::Serializer,
    block::TopoHeight
};
use crate::core::{
    error::BlockchainError,
    storage::{SledStorage, VersionedDelayedExecutionsProvider}
};

#[async_trait]
impl VersionedDelayedExecutionsProvider for SledStorage {
    async fn delete_delayed_executions_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete delayed executions at topoheight {}", topoheight);
        for el in Self::scan_prefix(self.snapshot.as_ref(), &self.contracts_delayed_executions, &topoheight.to_be_bytes()) {
            let prefixed_key = el?;

            // Delete this version from DB
            // We read the previous topoheight to check if we need to delete the balance
            Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.contracts_delayed_executions, &prefixed_key)?;
        }

        Ok(())
    }

    async fn delete_delayed_executions_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete delayed executions above topoheight {}", topoheight);
        for el in Self::iter_keys(self.snapshot.as_ref(), &self.contracts_delayed_executions) {
            let key = el?;
            let topo = u64::from_bytes(&key)?;

            if topo > topoheight {
                Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.contracts_delayed_executions, &key)?;
            }
        }

        Ok(())
    }

    async fn delete_delayed_executions_below_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete delayed executions below topoheight {}", topoheight);
        for el in Self::iter_keys(self.snapshot.as_ref(), &self.contracts_delayed_executions) {
            let key = el?;
            let topo = u64::from_bytes(&key)?;

            if topo < topoheight {
                Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.contracts_delayed_executions, &key)?;
            }
        }

        Ok(())
    }
}