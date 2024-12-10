use async_trait::async_trait;
use log::trace;
use xelis_common::{
    account::VersionedBalance,
    block::TopoHeight,
    crypto::{Hash, PublicKey},
    serializer::Serializer
};
use crate::core::{
    error::BlockchainError,
    storage::{
        BalanceProvider,
        SledStorage
    }
};

#[async_trait]
pub trait VersionedBalanceProvider {
    // delete versioned balances at topoheight
    async fn delete_versioned_balances_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // delete versioned balances above topoheight
    async fn delete_versioned_balances_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // delete versioned balances below topoheight
    async fn delete_versioned_balances_below_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;
}


#[async_trait]
impl VersionedBalanceProvider for SledStorage {
    async fn delete_versioned_balances_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned balances at topoheight {}", topoheight);
        // TODO: scan prefix support snapshot
        for el in self.versioned_balances.scan_prefix(&topoheight.to_be_bytes()) {
            let (key, value) = el?;
            // Delete this version from DB
            Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.versioned_balances, &key)?;

            // Deserialize keys part
            let asset = Hash::from_bytes(&key[40..72])?;
            let key = PublicKey::from_bytes(&key[8..40])?;

            let last_topoheight = self.get_last_topoheight_for_balance(&key, &asset).await?;
            if last_topoheight >= topoheight {
                // Deserialize value, it is needed to get the previous topoheight
                let versioned_balance = VersionedBalance::from_bytes(&value)?;
    
                // Now records changes, for each balances
                let db_key = self.get_balance_key_for(&key, &asset);
                if let Some(previous_topoheight) = versioned_balance.get_previous_topoheight() {
                    Self::insert_into_disk(self.snapshot.as_mut(), &self.balances, &db_key, &previous_topoheight.to_be_bytes())?;
                } else {
                    // if there is no previous topoheight, it means that this is the first version
                    // so we can delete the balance
                    Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.balances, &db_key)?;
                }
            }
        }
        Ok(())
    }

    async fn delete_versioned_balances_above_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("delete versioned balances above topoheight {}!", topoheight);
        Self::delete_versioned_tree_above_topoheight(&mut self.snapshot, &self.versioned_balances, topoheight)
    }

    async fn delete_versioned_balances_below_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("delete versioned balances below topoheight {}!", topoheight);
        Self::delete_versioned_tree_below_topoheight(&mut self.snapshot, &self.versioned_balances, topoheight)
    }
}