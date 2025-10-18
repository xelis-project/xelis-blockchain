use async_trait::async_trait;
use log::trace;
use xelis_common::{
    account::BalanceType,
    block::TopoHeight,
    serializer::{RawBytes, Serializer},
    versioned_type::Versioned
};
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::{SledStorage, VersionedBalanceProvider}
};

#[async_trait]
impl VersionedBalanceProvider for SledStorage {
    async fn delete_versioned_balances_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned balances at topoheight {}", topoheight);
        Self::delete_versioned_tree_at_topoheight(&mut self.snapshot, &self.balances, &self.versioned_balances, topoheight)?;
        Ok(())
    }

    async fn delete_versioned_balances_above_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("delete versioned balances above topoheight {}!", topoheight);
        Self::delete_versioned_tree_above_topoheight(&mut self.snapshot, &self.balances, &self.versioned_balances, topoheight, DiskContext::VersionedBalance)
    }

    async fn delete_versioned_balances_below_topoheight(&mut self, topoheight: u64, keep_last: bool) -> Result<(), BlockchainError> {
        trace!("delete versioned balances (keep last: {}) below topoheight {}!", keep_last, topoheight);
        if !keep_last {
            Self::delete_versioned_tree_below_topoheight(&mut self.snapshot, &self.balances, &self.versioned_balances, topoheight, keep_last, DiskContext::VersionedBalance)
        } else {
            // We need to search until we find the latest output version
            // And we delete everything below it

            // We check one account at a time
            let snapshot = self.snapshot.as_mut().map(|v| v.clone_mut());
            for el in Self::iter::<RawBytes, TopoHeight>(snapshot.as_ref(), &self.balances) {
                let (k, topo) = el?;

                // We fetch the last version to take its previous topoheight
                // And we loop on it to delete them all until the end of the chained data
                // But before deleting, we need to find if we are below a output balance
                let mut prev_version = Some(topo);
                let mut patched = false;
                while let Some(prev_topo) = prev_version.take() {
                    let key = Self::get_versioned_key(&k, prev_topo);

                    // Delete this version from DB if its below the threshold
                    if patched {
                        prev_version = Self::remove_from_disk(self.snapshot.as_mut(), &self.versioned_balances, &key)?;
                    } else {
                        // Load it so we can continue to loop over all next versions
                        let (tmp, ty) = self.load_from_disk::<(Option<u64>, BalanceType)>(&self.versioned_balances, &key, DiskContext::BalanceAtTopoHeight(prev_topo))?;
                        prev_version = tmp;

                        // We can only patch if we are below the threshold and contains an output
                        if prev_topo < topoheight && ty.contains_output() {
                            trace!("Patching versioned balance at topoheight {}", topoheight);
                            let mut data: Versioned<RawBytes> = Self::load_from_disk_internal(self.snapshot.as_ref(), &self.versioned_balances, &key, DiskContext::BalanceAtTopoHeight(prev_topo))?;
                            data.set_previous_topoheight(None);

                            Self::insert_into_disk(self.snapshot.as_mut(), &self.versioned_balances, &key, data.to_bytes())?;

                            // If this version contains an output, that means we can delete all others below
                            patched = true;
                        }
                    }
                }
            }

            Ok(())
        }
    }
}