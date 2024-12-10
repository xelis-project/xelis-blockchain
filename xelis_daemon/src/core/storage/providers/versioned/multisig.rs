use async_trait::async_trait;
use log::trace;
use xelis_common::{
    block::TopoHeight,
    crypto::PublicKey,
    serializer::Serializer
};
use crate::core::{
    error::BlockchainError,
    storage::{
        MultiSigProvider,
        SledStorage,
        VersionedMultiSig
    }
};

#[async_trait]
pub trait VersionedMultiSigProvider {
    // delete versioned multisigs at topoheight
    async fn delete_versioned_multisigs_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // delete versioned multisigs above topoheight
    async fn delete_versioned_multisigs_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // delete versioned multisigs below topoheight
    async fn delete_versioned_multisigs_below_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;
}

#[async_trait]
impl VersionedMultiSigProvider for SledStorage {
    async fn delete_versioned_multisigs_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned nonces at topoheight {}", topoheight);
        for el in self.versioned_multisigs.scan_prefix(&topoheight.to_be_bytes()) {
            let (key, value) = el?;
            // Delete this version from DB
            Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.versioned_multisigs, &key)?;

            // Deserialize keys part
            let key = PublicKey::from_bytes(&key[8..40])?;

            // Because of chain reorg, it may have been already deleted
            if let Some(last_topoheight) = self.get_last_topoheight_for_multisig(&key).await? {
                if last_topoheight >= topoheight {
                    // Deserialize value, it is needed to get the previous topoheight
                    let version = VersionedMultiSig::from_bytes(&value)?;
                    // Now records changes
                    if let Some(previous_topoheight) = version.get_previous_topoheight() {
                        self.set_last_topoheight_for_multisig(&key, previous_topoheight).await?;
                    } else {
                        // if there is no previous topoheight, it means that this is the first version
                        // so we can delete the balance
                        self.delete_last_topoheight_for_multisig(&key).await?;
                    }
                }
            }
        }

        Ok(())
    }

    async fn delete_versioned_multisigs_above_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("delete versioned multisigs above topoheight {}!", topoheight);
        Self::delete_versioned_tree_above_topoheight(&mut self.snapshot, &self.versioned_multisigs, topoheight)
    }

    async fn delete_versioned_multisigs_below_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("delete versioned multisigs below topoheight {}!", topoheight);
        Self::delete_versioned_tree_below_topoheight(&mut self.snapshot, &self.versioned_multisigs, topoheight)
    }
}