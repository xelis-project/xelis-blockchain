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
pub trait VersionedRegistrationsProvider {
    // delete versioned registrations at topoheight
    async fn delete_versioned_registrations_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // delete versioned registrations above topoheight
    async fn delete_versioned_registrations_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // delete versioned registrations below topoheight
    async fn delete_versioned_registrations_below_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;
}

#[async_trait]
impl VersionedRegistrationsProvider for SledStorage {
    async fn delete_versioned_registrations_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned registrations at topoheight {}", topoheight);
        // TODO: scan prefix support snapshot
        for el in self.registrations_prefixed.scan_prefix(&topoheight.to_be_bytes()).keys() {
            let key = el?;

            // Delete this version from DB
            Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.registrations_prefixed, &key)?;
            Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.registrations, &key[8..40])?;
        }

        trace!("delete versioned registrations at topoheight {} done!", topoheight);
        Ok(())
    }

    async fn delete_versioned_registrations_above_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("delete versioned registrations above topoheight {}", topoheight);
        for el in self.registrations_prefixed.iter().keys() {
            let key = el?;
            let topo = u64::from_bytes(&key[0..8])?;
            if topo > topoheight {
                Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.registrations_prefixed, &key)?;
                Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.registrations, &key[8..])?;
            }
        }

        Ok(())
    }

    async fn delete_versioned_registrations_below_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("delete versioned registrations below topoheight {}", topoheight);

        for el in self.registrations_prefixed.iter().keys() {
            let key = el?;
            let topo = u64::from_bytes(&key[0..8])?;
            if topo < topoheight {
                Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.registrations_prefixed, &key)?;
                Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.registrations, &key[8..])?;
            }
        }

        Ok(())
    }
}