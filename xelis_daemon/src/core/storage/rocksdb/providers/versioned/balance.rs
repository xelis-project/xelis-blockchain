use async_trait::async_trait;
use log::trace;
use rocksdb::Direction;
use xelis_common::{account::BalanceType, block::TopoHeight, serializer::RawBytes};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::{AccountId, AssetId, Column, IteratorMode},
        RocksStorage,
        VersionedBalanceProvider
    }
};

#[async_trait]
impl VersionedBalanceProvider for RocksStorage {
    // delete versioned balances at topoheight
    async fn delete_versioned_balances_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned balances at topoheight {}", topoheight);
        self.delete_versioned_at_topoheight(Column::Balances, Column::VersionedBalances, topoheight)
    }

    // delete versioned balances above topoheight
    async fn delete_versioned_balances_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned balances above topoheight {}", topoheight);
        self.delete_versioned_above_topoheight(Column::Balances, Column::VersionedBalances, topoheight)
    }

    // delete versioned balances below topoheight
    // Difference is, if we have
    async fn delete_versioned_balances_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        trace!("delete versioned balances below topoheight {}", topoheight);
        let start = topoheight.to_be_bytes();
        if keep_last {
            for res in Self::iter_owned_internal::<(AccountId, AssetId), TopoHeight>(&self.db, self.snapshot.as_ref(), IteratorMode::Start, Column::Balances)? {
                let ((account_id, asset_id), pointer) = res?;

                // We fetch the last version to take its previous topoheight
                // And we loop on it to delete them all until the end of the chained data
                // But before deleting, we need to find if we are below a output balance
                let mut prev_version = Some(pointer);
                let mut delete = false;
                while let Some(prev_topo) = prev_version {
                    let key = Self::get_versioned_account_balance_key(account_id, asset_id, prev_topo);

                    // Delete this version from DB if its below the threshold
                    if delete {
                        prev_version = self.load_from_disk(Column::VersionedBalances, &key)?;
                        Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedBalances, &key)?;
                    } else {
                        let (prev, ty) = self.load_from_disk::<_, (Option<u64>, BalanceType)>(Column::VersionedBalances, &key)?;
                        // If this version contains an output, that means we can delete all others below
                        if prev_topo < topoheight {
                            delete = ty.contains_output();
                        }

                        prev_version = prev;
                    }
                }
            }
        } else {
            for res in Self::iter_owned_internal::<RawBytes, ()>(&self.db, self.snapshot.as_ref(), IteratorMode::From(&start, Direction::Forward), Column::VersionedBalances)? {
                let (key, _) = res?;
                Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedBalances, &key)?;
            }
        }

        Ok(())
    }
}