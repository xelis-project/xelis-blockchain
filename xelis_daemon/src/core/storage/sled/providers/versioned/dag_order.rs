use log::{trace, debug};
use async_trait::async_trait;
use xelis_common::{
    block::TopoHeight,
    crypto::Hash,
};
use crate::core::{
    error::BlockchainError,
    storage::{SledStorage, VersionedDagOrderProvider}
};

#[async_trait]
impl VersionedDagOrderProvider for SledStorage {
    async fn delete_dag_order_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete dag order above topoheight {}", topoheight);

        for el in Self::iter::<TopoHeight, Hash>(self.snapshot.clone().as_ref(), &self.hash_at_topo) {
            let (topo, hash) = el?;

            if topo > topoheight {
                debug!("found hash {} at topoheight {} while threshold topoheight is at {}", hash, topo, topoheight);
                Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.hash_at_topo, &topo.to_be_bytes())?;
                Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.topo_by_hash, hash.as_bytes())?;
            }
        }

        Ok(())
    }
}