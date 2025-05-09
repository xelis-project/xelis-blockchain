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
        rocksdb::{
            Column,
            TopoHeightMetadata
        },
        BlockDagProvider,
        DagOrderProvider,
        DifficultyProvider,
        RocksStorage,
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
    fn get_block_reward_at_topo_height(&self, topoheight: TopoHeight) -> Result<u64, BlockchainError> {
        trace!("get block reward at topoheight {}", topoheight);
        self.get_metadata_at_topoheight(topoheight)
            .map(|metadata| metadata.rewards)
    }

    // Get the supply from topoheight
    async fn get_supply_at_topo_height(&self, topoheight: TopoHeight) -> Result<u64, BlockchainError> {
        trace!("get supply at topoheight {}", topoheight);
        self.get_metadata_at_topoheight(topoheight)
            .map(|metadata| metadata.emitted_supply)
    }

    // Get the burned supply from topoheight
    async fn get_burned_supply_at_topo_height(&self, topoheight: TopoHeight) -> Result<u64, BlockchainError> {
        trace!("get burned supply at topoheight {}", topoheight);
        self.get_metadata_at_topoheight(topoheight)
        .map(|metadata| metadata.burned_supply)
    }

    // Set the metadata for topoheight
    fn set_topoheight_metadata(&mut self, topoheight: TopoHeight, rewards: u64, emitted_supply: u64, burned_supply: u64) -> Result<(), BlockchainError> {
        trace!("set topoheight metadata {}", topoheight);
        let metadata = TopoHeightMetadata {
            rewards,
            emitted_supply,
            burned_supply
        };

        self.insert_into_disk(Column::TopoHeightMetadata, &topoheight.to_be_bytes(), &metadata)
    }
}

impl RocksStorage {
    pub fn get_metadata_at_topoheight(&self, topoheight: TopoHeight) -> Result<TopoHeightMetadata, BlockchainError> {
        trace!("get metadata at topoheight {}", topoheight);
        // TODO: cache
        self.load_from_disk(Column::TopoHeightMetadata, &topoheight.to_be_bytes())
    }
}