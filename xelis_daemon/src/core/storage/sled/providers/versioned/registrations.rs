use async_trait::async_trait;
use log::{debug, trace};
use xelis_common::{
    block::TopoHeight,
    serializer::Serializer
};
use crate::core::{
    error::BlockchainError,
    storage::{AccountProvider, SledStorage, VersionedRegistrationsProvider}
};

#[async_trait]
impl VersionedRegistrationsProvider for SledStorage {
    async fn delete_versioned_registrations_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned registrations at topoheight {}", topoheight);

        let snapshot = self.snapshot.clone();
        let mut deleted = 0;
        for el in Self::scan_prefix_raw(snapshot.as_ref(), &self.registrations_prefixed, &topoheight.to_be_bytes()) {
            let (key, _) = el?;

            // Delete this version from DB
            Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.registrations_prefixed, &key)?;
            if Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.registrations, &key[8..40])? {
                deleted += 1;
            }
        }

        if deleted > 0 {
            debug!("deleted {} accounts at topoheight {}", deleted, topoheight);
            self.store_accounts_count(self.count_accounts().await? - deleted)?;
        }

        trace!("delete versioned registrations at topoheight {} done!", topoheight);
        Ok(())
    }

    async fn delete_versioned_registrations_above_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("delete versioned registrations above topoheight {}", topoheight);

        let snapshot = self.snapshot.clone();
        let mut deleted = 0;
        for el in Self::iter_raw(snapshot.as_ref(), &self.registrations_prefixed) {
            let (key, _) = el?;
            let topo = TopoHeight::from_bytes(&key[0..8])?;
            if topo > topoheight {
                Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.registrations_prefixed, &key)?;
                if Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.registrations, &key[8..])? {
                    deleted += 1;
                }
            }
        }

        if deleted > 0 {
            debug!("deleted {} accounts above topoheight {}", deleted, topoheight);
            self.store_accounts_count(self.count_accounts().await? - deleted)?;
        }

        Ok(())
    }
}