use async_trait::async_trait;
use log::trace;
use xelis_common::{
    account::BalanceType,
    block::TopoHeight,
    serializer::Serializer
};
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::SledStorage
};

#[async_trait]
pub trait VersionedBalanceProvider {
    // delete versioned balances at topoheight
    async fn delete_versioned_balances_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // delete versioned balances above topoheight
    async fn delete_versioned_balances_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // delete versioned balances below topoheight
    async fn delete_versioned_balances_below_topoheight(&mut self, topoheight: TopoHeight, all: bool) -> Result<(), BlockchainError>;
}


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
            for el in self.balances.iter() {
                let (k, value) = el?;
                let topo = TopoHeight::from_bytes(&value)?;

                // We fetch the last version to take its previous topoheight
                // And we loop on it to delete them all until the end of the chained data
                // But before deleting, we need to find if we are below a output balance
                let mut prev_version = self.load_from_disk(&self.versioned_balances, &Self::get_versioned_key(&k, topo), DiskContext::BalanceAtTopoHeight(topo))?;
                let mut delete = false;
                while let Some(prev_topo) = prev_version {
                    let key = Self::get_versioned_key(&k, prev_topo);

                    // Delete this version from DB if its below the threshold
                    if delete {
                        prev_version = Self::remove_from_disk(self.snapshot.as_mut(), &self.versioned_balances, &key)?;
                    } else {
                        let (prev_topo, ty) = self.load_from_disk::<(Option<u64>, BalanceType)>(&self.versioned_balances, &key, DiskContext::BalanceAtTopoHeight(prev_topo))?;
                        // If this version contains an output, that means we can delete all others below
                        delete = ty.contains_output();
                        prev_version = prev_topo;
                    }
                }
            }

            Ok(())
        }
    }
}