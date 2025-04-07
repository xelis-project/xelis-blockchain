use log::{trace, debug};
use async_trait::async_trait;
use xelis_common::{
    block::TopoHeight,
    crypto::Hash,
    serializer::Serializer
};
use crate::core::{
    error::BlockchainError,
    storage::SledStorage
};

#[async_trait]
pub trait VersionedDagOrderProvider {
    // Delete every block hashes <=> topoheight relations
    async fn delete_dag_order_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;
}

#[async_trait]
impl VersionedDagOrderProvider for SledStorage {
    async fn delete_dag_order_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete dag order above topoheight {}", topoheight);

        for el in Self::iter(self.snapshot.as_ref(), &self.hash_at_topo) {
            let (key, value) = el?;
            let topo = TopoHeight::from_bytes(&key)?;
            if topo > topoheight {
                let hash = Hash::from_bytes(&value)?;
                debug!("found hash {} at topoheight {} while threshold topoheight is at {}", hash, topo, topoheight);
                Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.hash_at_topo, &key)?;
                Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.topo_by_hash, &value)?;
            }
        }

        Ok(())
    }
}