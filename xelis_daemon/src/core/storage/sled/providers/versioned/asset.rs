use async_trait::async_trait;
use log::trace;
use xelis_common::block::TopoHeight;
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::{SledStorage, VersionedAssetProvider}
};

#[async_trait]
impl VersionedAssetProvider for SledStorage {
    async fn delete_versioned_assets_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned assets at topoheight {}", topoheight);
        Self::delete_versioned_tree_at_topoheight(&mut self.snapshot, &self.assets, &self.versioned_assets, topoheight)
    }

    async fn delete_versioned_assets_above_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("delete versioned assets above topoheight {}", topoheight);
        Self::delete_versioned_tree_above_topoheight(&mut self.snapshot, &self.assets, &self.versioned_assets, topoheight, DiskContext::Asset)
    }

    // delete versioned assets below topoheight
    async fn delete_versioned_assets_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        trace!("delete versioned assets below topoheight {}", topoheight);
        Self::delete_versioned_tree_below_topoheight(&mut self.snapshot, &self.assets, &self.versioned_assets, topoheight, keep_last, DiskContext::Asset)
    }
}