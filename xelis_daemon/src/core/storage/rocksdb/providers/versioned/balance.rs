use async_trait::async_trait;
use log::trace;
use xelis_common::{
    account::BalanceType,
    block::TopoHeight,
    serializer::{RawBytes, Serializer},
    versioned::Versioned
};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::Column,
        RocksStorage,
        VersionedBalanceProvider
    }
};

#[async_trait]
impl VersionedBalanceProvider for RocksStorage {
    // delete versioned balances at topoheight
    async fn delete_versioned_balances_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned balances at topoheight {}", topoheight);
        self.delete_versioned_at_topoheight(Column::Balances, Column::VersionedBalances, topoheight).await
    }

    // delete versioned balances above topoheight
    async fn delete_versioned_balances_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned balances above topoheight {}", topoheight);
        self.delete_versioned_above_topoheight(Column::Balances, Column::VersionedBalances, topoheight).await
    }

    // delete versioned balances below topoheight
    // Difference is, if we have
    async fn delete_versioned_balances_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        trace!("delete versioned balances below topoheight {}", topoheight);
        if !keep_last {
            return self.delete_versioned_below_topoheight_default(Column::Balances, Column::VersionedBalances, topoheight, keep_last).await
        }

        self.run_blocking_mut(|s| {
            let snapshot = s.snapshot.clone();
            for res in Self::iter_raw_internal(&s.db, snapshot.as_ref(), crate::core::storage::rocksdb::IteratorMode::Start, Column::Balances)? {
                let (key, value) = res?;

                let bytes = RawBytes::from_bytes(&key)?.to_bytes();
                let mut versioned_key = vec![0; bytes.len() + 8];
                versioned_key[8..].copy_from_slice(&bytes);

                let mut prev_version = Some(TopoHeight::from_bytes(&value)?);
                let mut patched = false;
                while let Some(prev_topo) = prev_version.take() {
                    versioned_key[0..8].copy_from_slice(&prev_topo.to_be_bytes());

                    if patched {
                        prev_version = s.load_from_disk(Column::VersionedBalances, &versioned_key)?;
                        Self::remove_from_disk_internal(&s.db, s.snapshot.as_mut(), Column::VersionedBalances, &versioned_key)?;
                    } else {
                        let (tmp, ty): (Option<u64>, BalanceType) = s.load_from_disk(Column::VersionedBalances, &versioned_key)?;
                        prev_version = tmp;

                        if prev_topo <= topoheight && ty.contains_output() {
                            let mut data: Versioned<RawBytes> = s.load_from_disk(Column::VersionedBalances, &versioned_key)?;
                            data.set_previous_topoheight(None);

                            Self::insert_into_disk_internal(&s.db, s.snapshot.as_mut(), Column::VersionedBalances, &versioned_key, &data)?;
                            patched = true;
                        }
                    }
                }
            }

            Ok(())
        })
    }
}
