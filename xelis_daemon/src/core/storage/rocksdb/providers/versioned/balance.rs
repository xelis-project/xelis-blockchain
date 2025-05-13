use async_trait::async_trait;
use log::trace;
use xelis_common::{
    block::TopoHeight,
    crypto::PublicKey,
    serializer::RawBytes
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
        trace!("delete versioned balances at {}", topoheight);
        for res in Self::iter_owned_internal::<RawBytes, Option<TopoHeight>, _>(&self.db, self.snapshot.as_ref(), Some(topoheight.to_be_bytes()), Column::VersionedBalances)? {
            let (key, prev_topo) = res?;
            let k: PublicKey = self.load_from_disk(Column::AccountById, &key[8..16])?;
            trace!("delete versioned balance for {}", k.as_address(true));

            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedBalances, &key)?;
        
            let key_without_prefix = &key[8..];
            if let Some(pointer) = Self::load_optional_from_disk_internal::<_, TopoHeight>(&self.db, self.snapshot.as_ref(), Column::Balances, key_without_prefix)? {
                if pointer >= topoheight {
                    if let Some(prev_topo) = prev_topo {
                        Self::insert_into_disk_internal(&self.db, self.snapshot.as_mut(), Column::Balances, key_without_prefix, &prev_topo.to_be_bytes())?;
                    } else {
                        // No previous topoheight, we can delete the balance
                        trace!("deleting balance for {}", k.as_address(true));
                        Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::Balances, &key_without_prefix)?;
                    }
                }
            }
        }

        Ok(())
    }

    // delete versioned balances above topoheight
    async fn delete_versioned_balances_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        todo!()
    }

    // delete versioned balances below topoheight
    async fn delete_versioned_balances_below_topoheight(&mut self, topoheight: TopoHeight, all: bool) -> Result<(), BlockchainError> {
        todo!()
    }
}