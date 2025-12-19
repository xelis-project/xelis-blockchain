use log::{trace, debug};
use async_trait::async_trait;
use xelis_common::{
    block::TopoHeight,
    crypto::Hash,
};
use crate::core::{
    error::BlockchainError,
    storage::{DagOrderProvider, SledStorage, VersionedDagOrderProvider}
};

#[async_trait]
impl VersionedDagOrderProvider for SledStorage {
    // Delete the topoheight for a block hash
    async fn delete_dag_order_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete dag order at topoheight {}", topoheight);
        let hash = self.get_hash_at_topo_height(topoheight).await?;

        Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.topo_by_hash, hash.as_bytes())?;
        Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.hash_at_topo, &topoheight.to_be_bytes())?;

        if let Some(cache) = self.cache_mut().objects.as_ref().map(|o| &o.topo_by_hash_cache) {
            let mut topo = cache.lock().await;
            topo.pop(&hash);
        }

        if let Some(cache) = self.cache_mut().objects.as_ref().map(|o| &o.hash_at_topo_cache) {
            let mut hash_at_topo = cache.lock().await;
            hash_at_topo.pop(&topoheight);
        }

        Ok(())
    }

    async fn delete_dag_order_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete dag order above topoheight {}", topoheight);

        let snapshot = self.snapshot.clone();
        for el in Self::iter::<TopoHeight, Hash>(snapshot.as_ref(), &self.hash_at_topo) {
            let (topo, hash) = el?;

            if topo > topoheight {
                debug!("found hash {} at topoheight {} while threshold topoheight is at {}", hash, topo, topoheight);
                Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.hash_at_topo, &topo.to_be_bytes())?;
                Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.topo_by_hash, hash.as_bytes())?;
            }
        }

        if let Some(cache) = self.cache_mut().objects.as_ref().map(|o| &o.hash_at_topo_cache) {
            let mut hash_at_topo = cache.lock().await;
            hash_at_topo.clear();
        }

        if let Some(cache) = self.cache_mut().objects.as_ref().map(|o| &o.topo_by_hash_cache) {
            let mut topo = cache.lock().await;
            topo.clear();
        }

        Ok(())
    }
}