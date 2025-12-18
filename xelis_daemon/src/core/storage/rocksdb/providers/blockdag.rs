use async_trait::async_trait;
use log::trace;
use xelis_common::{
    block::{BlockHeader, TopoHeight},
    crypto::Hash,
    immutable::Immutable
};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::Column,
        types::TopoHeightMetadata,
        BlockDagProvider,
        DagOrderProvider,
        DifficultyProvider,
        RocksStorage
    }
};

#[async_trait]
impl BlockDagProvider for RocksStorage {
    // Get a block header & hash from its topoheight
    async fn get_block_header_at_topoheight(&self, topoheight: TopoHeight) -> Result<(Hash, Immutable<BlockHeader>), BlockchainError> {
        trace!("get block header at topoheight {}", topoheight);
        let hash = self.get_hash_at_topo_height(topoheight).await?;
        let header = self.get_block_header_by_hash(&hash).await?;
        Ok((hash, header))
    }

    // Get the block reward from using topoheight
    async fn get_block_reward_at_topo_height(&self, topoheight: TopoHeight) -> Result<u64, BlockchainError> {
        trace!("get block reward at topoheight {}", topoheight);
        self.get_metadata_at_topoheight(topoheight)
            .map(|metadata| metadata.block_reward)
    }

    // Get the supply from topoheight
    async fn get_emitted_supply_at_topo_height(&self, topoheight: TopoHeight) -> Result<u64, BlockchainError> {
        trace!("get supply at topoheight {}", topoheight);
        self.get_metadata_at_topoheight(topoheight)
            .map(|metadata| metadata.emitted_supply)
    }

    // Set the metadata for topoheight
    async fn set_metadata_at_topoheight(&mut self, topoheight: TopoHeight, metadata: TopoHeightMetadata) -> Result<(), BlockchainError> {
        trace!("set metadata at topoheight {}", topoheight);
        self.insert_into_disk(Column::TopoHeightMetadata, &topoheight.to_be_bytes(), &metadata)
    }

    // Set the metadata for topoheight
    async fn get_metadata_at_topoheight(&self, topoheight: TopoHeight) -> Result<TopoHeightMetadata, BlockchainError> {
        trace!("get metadata at topoheight {}", topoheight);
        self.load_from_disk(Column::TopoHeightMetadata, &topoheight.to_be_bytes())
    }
}

impl RocksStorage {
    pub fn get_metadata_at_topoheight(&self, topoheight: TopoHeight) -> Result<TopoHeightMetadata, BlockchainError> {
        trace!("get metadata at topoheight {}", topoheight);
        // TODO: cache
        self.load_from_disk(Column::TopoHeightMetadata, &topoheight.to_be_bytes())
    }
}