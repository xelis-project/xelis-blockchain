use anyhow::Context;
use pooled_arc::PooledArc;
use async_trait::async_trait;
use xelis_common::{
    block::TopoHeight,
    crypto::Hash,
};
use crate::core::{
    error::BlockchainError,
    storage::DagOrderProvider,
};
use super::super::MemoryStorage;

#[async_trait]
impl DagOrderProvider for MemoryStorage {
    async fn get_topo_height_for_hash(&self, hash: &Hash) -> Result<TopoHeight, BlockchainError> {
        self.topo_by_hash.get(hash)
            .copied()
            .with_context(|| format!("Topoheight not found for block {}", hash))
            .map_err(|e| e.into())
    }

    async fn set_topo_height_for_block(&mut self, hash: &Hash, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        let shared = PooledArc::from_ref(hash);
        self.topo_by_hash.insert(shared.clone(), topoheight);
        self.hash_at_topo.insert(topoheight, shared);
        Ok(())
    }

    async fn is_block_topological_ordered(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        let Some(&topo) = self.topo_by_hash.get(hash) else {
            return Ok(false);
        };
        let Some(stored_hash) = self.hash_at_topo.get(&topo) else {
            return Ok(false);
        };
        Ok(*stored_hash == *hash)
    }

    async fn get_hash_at_topo_height(&self, topoheight: TopoHeight) -> Result<Hash, BlockchainError> {
        self.hash_at_topo.get(&topoheight)
            .map(|h| h.as_ref().clone())
            .with_context(|| format!("Hash not found for topoheight {}", topoheight))
            .map_err(|e| e.into())
    }

    async fn has_hash_at_topoheight(&self, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        Ok(self.hash_at_topo.contains_key(&topoheight))
    }

    async fn get_orphaned_blocks<'a>(&'a self) -> Result<impl Iterator<Item = Result<Hash, BlockchainError>> + 'a, BlockchainError> {
        Ok(self.blocks.keys()
            .filter(|hash| !self.topo_by_hash.contains_key(hash.as_ref()))
            .map(|h| Ok(h.as_ref().clone())))
    }
}
