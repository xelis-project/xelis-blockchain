use async_trait::async_trait;
use log::trace;
use xelis_common::{
    crypto::Hash,
    serializer::Serializer
};
use crate::core::{
    error::BlockchainError,
    storage::SledStorage,
};

// This trait is used for find_tip_work_score to provide topoheight of each blocks
#[async_trait]
pub trait DagOrderProvider {
    async fn get_topo_height_for_hash(&self, hash: &Hash) -> Result<u64, BlockchainError>;
    async fn set_topo_height_for_block(&mut self, hash: &Hash, topoheight: u64) -> Result<(), BlockchainError>;
    async fn is_block_topological_ordered(&self, hash: &Hash) -> bool;
    async fn get_hash_at_topo_height(&self, topoheight: u64) -> Result<Hash, BlockchainError>;
}

#[async_trait]
impl DagOrderProvider for SledStorage {
    async fn set_topo_height_for_block(&mut self, hash: &Hash, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("set topo height for {} at {}", hash, topoheight);
        self.topo_by_hash.insert(hash.as_bytes(), topoheight.to_bytes())?;
        self.hash_at_topo.insert(topoheight.to_be_bytes(), hash.as_bytes())?;

        // save in cache
        if let Some(cache) = &self.topo_by_hash_cache {
            let mut topo = cache.lock().await;
            topo.put(hash.clone(), topoheight);
        }

        if let Some(cache) = &self.hash_at_topo_cache {
            let mut hash_at_topo = cache.lock().await;
            hash_at_topo.put(topoheight, hash.clone());
        }

        Ok(())
    }

    async fn is_block_topological_ordered(&self, hash: &Hash) -> bool {
        trace!("is block topological ordered: {}", hash);
        let topoheight = match self.get_topo_height_for_hash(&hash).await {
            Ok(topoheight) => topoheight,
            Err(e) => {
                trace!("Error while checking if block {} is ordered: {}", hash, e);
                return false
            }
        };

        let hash_at_topo = match self.get_hash_at_topo_height(topoheight).await {
            Ok(hash_at_topo) => hash_at_topo,
            Err(e) => {
                trace!("Error while checking if a block hash is ordered at topo {}: {}", topoheight, e);
                return false
            }
        };
        hash_at_topo == *hash
    }

    async fn get_topo_height_for_hash(&self, hash: &Hash) -> Result<u64, BlockchainError> {
        trace!("get topoheight for hash: {}", hash);
        self.get_cacheable_data(&self.topo_by_hash, &self.topo_by_hash_cache, &hash).await
    }

    async fn get_hash_at_topo_height(&self, topoheight: u64) -> Result<Hash, BlockchainError> {
        trace!("get hash at topoheight: {}", topoheight);
        let hash = if let Some(cache) = &self.hash_at_topo_cache {
            let mut hash_at_topo = cache.lock().await;
            if let Some(value) = hash_at_topo.get(&topoheight) {
                return Ok(value.clone())
            }
            let hash: Hash = self.load_from_disk(&self.hash_at_topo, &topoheight.to_be_bytes())?;
            hash_at_topo.put(topoheight, hash.clone());
            hash
        } else {
            self.load_from_disk(&self.hash_at_topo, &topoheight.to_be_bytes())?
        };

        Ok(hash)
    }
}