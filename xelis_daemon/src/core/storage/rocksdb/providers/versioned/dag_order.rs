use async_trait::async_trait;
use log::{debug, trace};
use xelis_common::{block::TopoHeight, crypto::Hash};
use crate::core::{
    error::BlockchainError,
    storage::{
        DagOrderProvider, RocksStorage, VersionedDagOrderProvider, rocksdb::{
            Column,
            IteratorMode
        }, snapshot::Direction
    }
};

#[async_trait]
impl VersionedDagOrderProvider for RocksStorage {
    // Delete the topoheight for a block hash
    async fn delete_dag_order_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete topo height for block {}", topoheight);
        let hash = self.get_hash_at_topo_height(topoheight).await?;

        self.remove_from_disk(Column::TopoByHash, hash)?;
        self.remove_from_disk(Column::HashAtTopo, topoheight.to_be_bytes())
    }

    // Delete every block hashes <=> topoheight relations
    async fn delete_dag_order_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete dag order above topoheight {}", topoheight);

        let start = (topoheight + 1).to_be_bytes();
        let snapshot = self.snapshot.clone();
        for el in Self::iter_internal::<TopoHeight, Hash>(&self.db, snapshot.as_ref(), IteratorMode::From(&start, Direction::Forward), Column::HashAtTopo)? {
            let (topo, hash) = el?;
            debug!("found hash {} at topoheight {} while threshold topoheight is at {}", hash, topo, topoheight);
            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::HashAtTopo, &topo.to_be_bytes())?;
            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::TopoByHash, &hash)?;
        }

        Ok(())
    }
}