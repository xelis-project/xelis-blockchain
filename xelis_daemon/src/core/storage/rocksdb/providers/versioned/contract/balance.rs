use async_trait::async_trait;
use log::trace;
use xelis_common::{
    block::TopoHeight,
    serializer::{RawBytes, Serializer},
    versioned::Versioned,
};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::{Column, IteratorMode},
        RocksStorage,
        VersionedContractBalanceProvider
    }
};

#[async_trait]
impl VersionedContractBalanceProvider for RocksStorage {
    async fn delete_versioned_contract_balances_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned contract balances at topoheight {}", topoheight);
        self.delete_versioned_at_topoheight(Column::ContractsBalances, Column::VersionedContractsBalances, topoheight).await
    }

    async fn delete_versioned_contract_balances_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned contract balances above topoheight {}", topoheight);
        self.delete_versioned_above_topoheight(Column::ContractsBalances, Column::VersionedContractsBalances, topoheight).await
    }

    async fn delete_versioned_contract_balances_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        trace!("delete versioned contract balances below topoheight {}", topoheight);
        self.run_blocking_mut(|s| {
            if !keep_last {
                return s.delete_versioned_data_below_topoheight(
                    Column::VersionedContractsBalances,
                    topoheight,
                );
            }

            let snapshot = s.snapshot.clone();
            for res in Self::iter_raw_internal(
                &s.db,
                snapshot.as_ref(),
                IteratorMode::Start,
                Column::ContractsBalances,
            )? {
                let (key, value) = res?;
                let mut previous_topoheight = Some(TopoHeight::from_bytes_non_strict(&value)?);
                let mut patched = false;

                while let Some(previous) = previous_topoheight.take() {
                    let mut versioned_key = Vec::with_capacity(8 + key.len());
                    versioned_key.extend_from_slice(&previous.to_be_bytes());
                    versioned_key.extend_from_slice(&key);

                    previous_topoheight = s.load_from_disk(
                        Column::VersionedContractsBalances,
                        &versioned_key,
                    )?;

                    if patched {
                        Self::remove_from_disk_internal(
                            &s.db,
                            s.snapshot.as_mut(),
                            Column::VersionedContractsBalances,
                            &versioned_key,
                        )?;
                    } else if previous <= topoheight {
                        patched = true;
                        let mut version: Versioned<RawBytes> = s.load_from_disk(
                            Column::VersionedContractsBalances,
                            &versioned_key,
                        )?;
                        version.set_previous_topoheight(None);
                        Self::insert_into_disk_internal(
                            &s.db,
                            s.snapshot.as_mut(),
                            Column::VersionedContractsBalances,
                            &versioned_key,
                            &version,
                        )?;
                    }
                }
            }

            Ok(())
        })
    }
}