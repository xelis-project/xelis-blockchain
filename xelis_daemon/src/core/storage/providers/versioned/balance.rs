use std::collections::{hash_map::Entry, HashMap};

use async_trait::async_trait;
use log::{debug, trace};
use sled::IVec;
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
    async fn delete_versioned_balances_below_topoheight(&mut self, topoheight: TopoHeight, all: bool) -> Result<(), BlockchainError>;
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

    async fn delete_versioned_balances_below_topoheight(&mut self, topoheight: u64, keep_last: bool) -> Result<(), BlockchainError> {
        trace!("delete versioned balances (keep last: {}) below topoheight {}!", keep_last, topoheight);
        if !keep_last {
            Self::delete_versioned_tree_below_topoheight(&mut self.snapshot, &self.versioned_balances, topoheight)
        } else {
            // We need to search until we find the latest output version
            // And we delete everything below it

            // To prevent too much IO, we keep the output version in memory for each key (public key + asset)
            let mut last_outputs: HashMap<IVec, Option<TopoHeight>> = HashMap::new();
            for el in self.versioned_balances.iter().keys() {
                let k = el?;
                let topo = TopoHeight::from_bytes(&k[..8])?;
                if topo < topoheight {
                    let output_topo = match last_outputs.entry(k.subslice(8, 64)) {
                        Entry::Occupied(e) => e.get().as_ref().copied(),
                        Entry::Vacant(e) => {
                            let key = PublicKey::from_bytes(&k[8..40])?;
                            let asset = Hash::from_bytes(&k[40..72])?;
                            let res = self.get_output_balance_at_maximum_topoheight(&key, &asset, topoheight).await?
                                .map(|(v, _)| v);

                            e.insert(res);
                            res
                        }
                    };

                    if let Some(output_topo) = output_topo {
                        if topo < output_topo {
                            debug!("delete versioned balance at topoheight {} (output: {}) for key {:?}", topo, output_topo, &k[8..40]);
                            Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.versioned_balances, &k)?;
                        }
                    }
                }
            }

            Ok(())
        }
    }
}