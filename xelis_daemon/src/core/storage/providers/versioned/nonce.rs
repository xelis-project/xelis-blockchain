use async_trait::async_trait;
use log::trace;
use xelis_common::{
    account::VersionedNonce,
    block::TopoHeight,
    crypto::PublicKey,
    serializer::Serializer
};
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::{
        NonceProvider,
        SledStorage
    }
};

#[async_trait]
pub trait VersionedNonceProvider {
    // delete versioned nonces at topoheight
    async fn delete_versioned_nonces_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // delete versioned nonces above topoheight
    async fn delete_versioned_nonces_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // delete versioned nonces below topoheight
    async fn delete_versioned_nonces_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError>;
}

#[async_trait]
impl VersionedNonceProvider for SledStorage {
    async fn delete_versioned_nonces_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned nonces at topoheight {}", topoheight);
        // TODO: scan prefix support snapshot
        for el in self.versioned_nonces.scan_prefix(&topoheight.to_be_bytes()) {
            let (key, value) = el?;
            // Delete this version from DB
            Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.versioned_nonces, &key)?;

            // Deserialize keys part
            let key = PublicKey::from_bytes(&key[8..40])?;

            // Because of chain reorg, it may have been already deleted
            if let Ok(last_topoheight) = self.get_last_topoheight_for_nonce(&key).await {
                if last_topoheight >= topoheight {
                    // Deserialize value, it is needed to get the previous topoheight
                    let version = VersionedNonce::from_bytes(&value)?;
                    // Now records changes
                    if let Some(previous_topoheight) = version.get_previous_topoheight() {
                        self.set_last_topoheight_for_nonce(&key, previous_topoheight).await?;
                    } else {
                        // if there is no previous topoheight, it means that this is the first version
                        // so we can delete the balance
                        self.delete_last_topoheight_for_nonce(&key).await?;
                    }
                }
            }
        }

        trace!("delete versioned nonces at topoheight {} done!", topoheight);
        Ok(())
    }

    async fn delete_versioned_nonces_above_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("delete versioned nonces above topoheight {}!", topoheight);
        Self::delete_versioned_tree_above_topoheight(&mut self.snapshot, &self.versioned_nonces, topoheight)
    }

    async fn delete_versioned_nonces_below_topoheight(&mut self, topoheight: u64, keep_last: bool) -> Result<(), BlockchainError> {
        trace!("delete versioned nonces below topoheight {}!", topoheight);
        Self::delete_versioned_tree_below_topoheight(&mut self.snapshot, &self.nonces, &self.versioned_nonces, topoheight, keep_last, DiskContext::NonceAtTopoHeight)
    }
}