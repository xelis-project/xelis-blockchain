use async_trait::async_trait;
use log::trace;
use xelis_common::{
    block::TopoHeight,
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

    // delete versioned assets below topoheight
    async fn delete_versioned_assets_below_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;
}

#[async_trait]
impl VersionedAssetProvider for SledStorage {
    async fn delete_versioned_assets_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned assets at topoheight {}", topoheight);
        // TODO: scan prefix support snapshot
        for el in self.assets_prefixed.scan_prefix(&topoheight.to_be_bytes()).keys() {
            let key = el?;

            // Delete this version from DB
            Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.assets_prefixed, &key)?;
            Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.assets, &key[8..])?;
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
            }
        }

        Ok(())
    }

    async fn delete_versioned_assets_below_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("delete versioned assets below topoheight {}", topoheight);
        let mut buf = [0u8; 40];
        for el in self.assets.iter() {
            let (key, value) = el?;
            let topo = u64::from_bytes(&value[0..8])?;
            if topo < topoheight {
                buf[0..8].copy_from_slice(&value);
                buf[8..40].copy_from_slice(&key);

                Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.assets_prefixed, &buf)?;
                Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.assets, &key)?;
            }
        }

        Ok(())
    }
}