use async_trait::async_trait;
use log::{debug, trace};
use xelis_common::{block::TopoHeight, crypto::Hash};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::{
            Column,
            IteratorMode
        },
        snapshot::Direction,
        RocksStorage,
        VersionedDagOrderProvider
    }
};

#[async_trait]
impl VersionedDagOrderProvider for RocksStorage {
    // Delete every block hashes <=> topoheight relations
    async fn delete_dag_order_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete dag order above topoheight {}", topoheight);

        let start = (topoheight + 1).to_be_bytes();
        for el in Self::iter_owned_internal::<TopoHeight, Hash>(&self.db, self.snapshot.as_ref(), IteratorMode::From(&start, Direction::Forward), Column::HashAtTopo)? {
            let (topo, hash) = el?;
            debug!("found hash {} at topoheight {} while threshold topoheight is at {}", hash, topo, topoheight);
            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::HashAtTopo, &topo.to_be_bytes())?;
            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::TopoByHash, &hash)?;
        }

        Ok(())
    }
}