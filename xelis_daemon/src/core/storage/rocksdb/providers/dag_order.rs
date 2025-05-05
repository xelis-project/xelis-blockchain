use async_trait::async_trait;
use xelis_common::{block::TopoHeight, crypto::Hash};

use crate::core::{
    error::BlockchainError,
    storage::{Column, DagOrderProvider, RocksStorage}
};

#[async_trait]
impl DagOrderProvider for RocksStorage {
    async fn get_topo_height_for_hash(&self, hash: &Hash) -> Result<TopoHeight, BlockchainError> {
        self.load_from_disk(Column::TopoByHash, hash)
    }

    async fn set_topo_height_for_block(&mut self, hash: &Hash, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        self.insert_into_disk(Column::TopoByHash, hash, &topoheight)?;
        self.insert_into_disk(Column::HashAtTopo, &topoheight, hash)
    }

    async fn is_block_topological_ordered(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        let Ok(topo_by_hash) = self.get_topo_height_for_hash(hash).await else {
            return Ok(false)
        };
        let Ok(hash_at_topo) = self.get_hash_at_topo_height(topo_by_hash).await else {
            return Ok(false)
        };

        Ok(hash_at_topo == *hash)
    }

    async fn get_hash_at_topo_height(&self, topoheight: TopoHeight) -> Result<Hash, BlockchainError> {
        self.load_from_disk(Column::HashAtTopo, &topoheight.to_be_bytes())
    }

    async fn has_hash_at_topoheight(&self, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        self.contains_data(Column::HashAtTopo, &topoheight.to_be_bytes())
    }
}