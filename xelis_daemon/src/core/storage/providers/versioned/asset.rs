use async_trait::async_trait;
use log::trace;
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
pub trait VersionedAssetProvider {
    // delete versioned assets at topoheight
    async fn delete_versioned_assets_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // delete versioned assets above topoheight
    async fn delete_versioned_assets_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;
}

#[async_trait]
impl VersionedAssetProvider for SledStorage {
    async fn delete_versioned_assets_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned assets at topoheight {}", topoheight);
        for el in Self::scan_prefix(self.snapshot.as_ref(), &self.assets_prefixed, &topoheight.to_be_bytes()) {
            let key = el?;

            // Delete this version from DB
            Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.assets_prefixed, &key)?;
            Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.assets, &key[8..])?;


            if let Some(cache) = self.assets_cache.as_mut() {
                cache.get_mut().pop(&Hash::from_bytes(&key[8..])?);
            }
        }

        trace!("delete versioned assets at topoheight {} done!", topoheight);
        Ok(())
    }

    async fn delete_versioned_assets_above_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("delete versioned assets above topoheight {}", topoheight);
        for el in self.assets_prefixed.iter().keys() {
            let key = el?;
            let topo = u64::from_bytes(&key[0..8])?;
            if topo > topoheight {
                Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.assets, &key[8..])?;
                Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.assets_prefixed, &key)?;

                if let Some(cache) = self.assets_cache.as_mut() {
                    cache.get_mut().pop(&Hash::from_bytes(&key[8..])?);
                }
            }
        }

        Ok(())
    }
}