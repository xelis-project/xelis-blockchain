use async_trait::async_trait;
use xelis_common::{
    block::TopoHeight,
    crypto::PublicKey,
    serializer::Serializer
};
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::{MultiSigProvider, SledStorage, VersionedMultiSig}
};
use log::trace;

#[async_trait]
impl MultiSigProvider for SledStorage {
    async fn get_last_topoheight_for_multisig(&self, account: &PublicKey) -> Result<Option<TopoHeight>, BlockchainError> {
        trace!("get last topoheight for multisig");
        self.load_optional_from_disk(&self.multisig, account.as_bytes())
    }

    async fn get_multisig_at_topoheight_for<'a>(&'a self, account: &PublicKey, topoheight: TopoHeight) -> Result<VersionedMultiSig<'a>, BlockchainError> {
        trace!("get multisig at topoheight {}", topoheight);
        self.load_from_disk(&self.versioned_multisigs, &self.get_versioned_multisig_key(account, topoheight), DiskContext::MultisigAtTopoHeight(topoheight))
    }

    async fn delete_last_topoheight_for_multisig(&mut self, account: &PublicKey) -> Result<(), BlockchainError> {
        trace!("delete last topoheight for multisig");
        Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.multisig, account.as_bytes())?;
        Ok(())
    }

    async fn get_multisig_at_maximum_topoheight_for<'a>(&'a self, account: &PublicKey, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedMultiSig<'a>)>, BlockchainError> {
        trace!("get multisig at maximum topoheight {}", maximum_topoheight);
        let mut previous_topoheight = if self.has_multisig_at_exact_topoheight(account, maximum_topoheight).await? {
            Some(maximum_topoheight)
        } else {
            self.get_last_topoheight_for_multisig(account).await?
        };

        while let Some(topoheight) = previous_topoheight {
            if topoheight <= maximum_topoheight {
                let version = self.get_multisig_at_topoheight_for(account, topoheight).await?;
                return Ok(Some((topoheight, version)))
            }

            previous_topoheight = self.load_from_disk(&self.versioned_multisigs, &self.get_versioned_multisig_key(account, topoheight), DiskContext::MultisigAtTopoHeight(topoheight))?;
        }

        Ok(None)
    }

    async fn has_multisig(&self, account: &PublicKey) -> Result<bool, BlockchainError> {
        trace!("has multisig");
        let Some(topoheight) = self.get_last_topoheight_for_multisig(account).await? else {
            return Ok(false)
        };

        let version = self.get_multisig_at_topoheight_for(account, topoheight).await?;
        Ok(version.get().is_some())
    }

    async fn has_multisig_at_exact_topoheight(&self, account: &PublicKey, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("has multisig at exact topoheight {}", topoheight);
        self.contains_data(&self.versioned_multisigs, &self.get_versioned_multisig_key(account, topoheight))
    }

    async fn set_last_multisig_to<'a>(&mut self, account: &PublicKey, topoheight: TopoHeight, multisig: VersionedMultiSig<'a>) -> Result<(), BlockchainError> {
        trace!("set last multisig to topoheight {}", topoheight);
        let key: [u8; 40] = self.get_versioned_multisig_key(account, topoheight);
        Self::insert_into_disk(self.snapshot.as_mut(), &self.versioned_multisigs, &key, multisig.to_bytes())?;
        Self::insert_into_disk(self.snapshot.as_mut(), &self.multisig, account.as_bytes(), &topoheight.to_be_bytes())?;

        Ok(())
    }
}

impl SledStorage {
    // Get the key for the multisig storage
    pub(super) fn get_versioned_multisig_key(&self, account: &PublicKey, topoheight: TopoHeight) -> [u8; 40] {
        let mut key = [0; 40];
        key[..32].copy_from_slice(account.as_bytes());
        key[32..].copy_from_slice(&topoheight.to_be_bytes());
        key
    }
}