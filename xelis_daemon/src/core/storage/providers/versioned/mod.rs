mod balance;
mod contract;
mod multisig;
mod nonce;
mod registrations;
mod asset;

use async_trait::async_trait;
use log::trace;
use sled::Tree;
use xelis_common::{
    block::TopoHeight,
    serializer::{NoTransform, Serializer},
    versioned_type::Versioned
};
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::{
        SledStorage,
        Snapshot
    }
};
use balance::VersionedBalanceProvider;
use contract::*;
use multisig::VersionedMultiSigProvider;
use nonce::VersionedNonceProvider;
use registrations::VersionedRegistrationsProvider;
use asset::VersionedAssetProvider;

// Every versioned key should start with the topoheight in order to be able to delete them easily
#[async_trait]
pub trait VersionedProvider:
    VersionedBalanceProvider
    + VersionedNonceProvider
    + VersionedMultiSigProvider
    + VersionedContractProvider
    + VersionedRegistrationsProvider
    + VersionedContractDataProvider
    + VersionedAssetProvider {

    // Delete versioned data at topoheight
    async fn delete_versioned_data_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        self.delete_versioned_balances_at_topoheight(topoheight).await?;
        self.delete_versioned_nonces_at_topoheight(topoheight).await?;
        self.delete_versioned_multisigs_at_topoheight(topoheight).await?;
        self.delete_versioned_registrations_at_topoheight(topoheight).await?;
        self.delete_versioned_contracts_at_topoheight(topoheight).await?;
        self.delete_versioned_contract_data_at_topoheight(topoheight).await?;

        if topoheight > 0 {
            self.delete_versioned_assets_at_topoheight(topoheight).await?;
        }

        Ok(())
    }

    // Delete versioned data below topoheight
    // Special case for versioned balances:
    // Because users can link a TX to an old versioned balance, we need to keep track of them until the latest spent version
    async fn delete_versioned_data_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        self.delete_versioned_balances_below_topoheight(topoheight, keep_last).await?;
        self.delete_versioned_nonces_below_topoheight(topoheight, keep_last).await?;
        self.delete_versioned_multisigs_below_topoheight(topoheight, keep_last).await?;
        self.delete_versioned_contracts_below_topoheight(topoheight, keep_last).await?;
        self.delete_versioned_contract_data_below_topoheight(topoheight, keep_last).await?;

        Ok(())
    }

    // Delete versioned data above topoheight
    async fn delete_versioned_data_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        self.delete_versioned_balances_above_topoheight(topoheight).await?;
        self.delete_versioned_nonces_above_topoheight(topoheight).await?;
        self.delete_versioned_multisigs_above_topoheight(topoheight).await?;
        self.delete_versioned_registrations_above_topoheight(topoheight).await?;
        self.delete_versioned_contracts_above_topoheight(topoheight).await?;
        self.delete_versioned_contract_data_above_topoheight(topoheight).await?;
        self.delete_versioned_assets_above_topoheight(topoheight).await?;
        Ok(())
    }
}

impl VersionedProvider for SledStorage {}

impl SledStorage {
    fn delete_versioned_tree_above_topoheight(snapshot: &mut Option<Snapshot>, tree: &Tree, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("delete versioned nonces above topoheight {}", topoheight);
        for el in tree.iter().keys() {
            let key = el?;
            let topo = u64::from_bytes(&key[0..8])?;
            if topo > topoheight {
                Self::remove_from_disk_without_reading(snapshot.as_mut(), tree, &key)?;
            }
        }
        Ok(())
    }

    fn delete_versioned_tree_below_topoheight(
        snapshot: &mut Option<Snapshot>,
        tree_pointer: &Tree,
        tree_versioned: &Tree,
        topoheight: u64,
        keep_last: bool,
        context: DiskContext,
    ) -> Result<(), BlockchainError> {
        trace!("delete versioned nonces below topoheight {}", topoheight);
        if keep_last {
            for el in tree_pointer.iter() {
                let (key, value) = el?;
                let topo = u64::from_bytes(&value)?;

                // We fetch the last version to take its previous topoheight
                // And we loop on it to delete them all until the end of the chained data
                let mut prev_version = Self::load_from_disk_internal::<Option<u64>>(snapshot.as_ref(), tree_versioned, &Self::get_versioned_key(&key, topo), context)?;
                let mut patched = false;
                while let Some(prev_topo) = prev_version {
                    let key = Self::get_versioned_key(&key, prev_topo);

                    // Delete this version from DB if its below the threshold
                    if patched {
                        prev_version = Self::remove_from_disk(snapshot.as_mut(), &tree_versioned, &key)?;
                    } else {
                        prev_version = Self::load_from_disk_internal(snapshot.as_ref(), tree_versioned, &key, context)?;
                        if prev_version.filter(|v| *v < topoheight).is_some() {
                            trace!("Patching versioned data at topoheight {}", topoheight);
                            patched = true;
                            let mut data: Versioned<NoTransform> = Self::load_from_disk_internal(snapshot.as_ref(), tree_versioned, &key, context)?;
                            data.set_previous_topoheight(None);
                            tree_versioned.insert(key, data.to_bytes())?;
                        }
                    }
                }
            }
        } else {
            for el in tree_versioned.iter().keys() {
                let key = el?;
                let topo = u64::from_bytes(&key[0..8])?;
                if topo < topoheight {
                    Self::remove_from_disk_without_reading(snapshot.as_mut(), tree_versioned, &key)?;
                }
            }
        }
        Ok(())
    }

    // Versioned key is a key that starts with the topoheight
    pub fn get_versioned_key<T: AsRef<[u8]>>(data: T, topoheight: TopoHeight) -> Vec<u8> {
        let bytes = data.as_ref();
        let mut buf = Vec::with_capacity(8 + bytes.len());
        buf.extend(topoheight.to_be_bytes());
        buf.extend(bytes);
        buf
    }
}