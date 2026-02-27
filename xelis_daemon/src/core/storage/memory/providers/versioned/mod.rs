mod balance;
mod nonce;
mod multisig;
mod registrations;
mod asset;
mod asset_supply;
mod dag_order;
mod cache;
mod contract;

use std::collections::BTreeMap;

use xelis_common::{block::TopoHeight, versioned_type::TopoHeightVersioned};

use crate::core::storage::{VersionedProvider, MemoryStorage};

impl VersionedProvider for MemoryStorage {}


impl MemoryStorage {
    /// Helper function to delete versioned data below topoheight
    /// It must check that its not the only version, as we must keep last version of data, even if its below the topoheight
    #[inline(always)]
    pub(super) fn delete_versioned_data_below_topoheight<T: TopoHeightVersioned>(data: &mut BTreeMap<TopoHeight, T>, mut topoheight: TopoHeight, keep_last: bool) {
        if keep_last {
            if let Some(last_entry) = data.last_key_value() {
                if *last_entry.0 <= topoheight {
                    // If the last entry is below or at the topoheight, we must keep it, so we set the topoheight to the one of the last entry
                    topoheight = *last_entry.0;
                }
            } else {
                // No entry, nothing to delete
                return;
            }
        }
    
        let mut to_keep = data.split_off(&topoheight);
        to_keep.first_entry()
            .map(|mut entry| {
                entry.get_mut()
                    .set_previous(None);
            });
    
        *data = to_keep;
    }
}