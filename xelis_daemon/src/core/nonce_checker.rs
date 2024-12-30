use std::collections::HashMap;

use indexmap::IndexMap;
use log::trace;
use xelis_common::{
    account::Nonce,
    block::TopoHeight,
    crypto::PublicKey
};

use super::{storage::Storage, error::BlockchainError};

struct AccountEntry {
    initial_nonce: Nonce,
    expected_nonce: Nonce,
    used_nonces: IndexMap<Nonce, TopoHeight>
}

impl AccountEntry {
    pub fn new(nonce: Nonce) -> Self {
        Self {
            initial_nonce: nonce,
            expected_nonce: nonce,
            used_nonces: IndexMap::new()
        }
    }

    pub fn contains_nonce(&self, nonce: &Nonce) -> bool {
        self.used_nonces.contains_key(nonce)
    }

    pub fn insert_nonce_at_topoheight(&mut self, nonce: Nonce, topoheight: TopoHeight) -> bool {
        trace!("insert nonce {} at topoheight {}, (expected: {})", nonce, topoheight, self.expected_nonce);
        if self.contains_nonce(&nonce) || nonce != self.expected_nonce {
            return false;
        }

        self.expected_nonce = nonce + 1;
        self.used_nonces.insert(nonce, topoheight);

        true
    }
}

// A simple cache that checks if a nonce has already been used
// Stores the topoheight of the block that used the nonce
pub struct NonceChecker {
    cache: HashMap<PublicKey, AccountEntry>,
}

impl NonceChecker {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new()
        }
    }

    // Undo the nonce usage
    // We remove it from the used nonces list and revert the expected nonce to the previous nonce if present.
    pub fn undo_nonce(&mut self, key: &PublicKey, nonce: Nonce) {
        if let Some(entry) = self.cache.get_mut(key) {
            entry.used_nonces.shift_remove(&nonce);

            if let Some((prev_nonce, _)) = entry.used_nonces.last() {
                entry.expected_nonce = *prev_nonce + 1;
            } else {
                entry.expected_nonce = entry.initial_nonce;
            }
        }
    }

    // Key may be cloned on first entry
    // Returns false if nonce is already used
    pub async fn use_nonce<S: Storage>(&mut self, storage: &S, key: &PublicKey, nonce: Nonce, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("use_nonce {} for {} at topoheight {}", nonce, key.as_address(storage.is_mainnet()), topoheight);

        match self.cache.get_mut(key) {
            Some(entry) => {
                if !entry.insert_nonce_at_topoheight(nonce, topoheight) {
                    return Ok(false);
                }
            },
            None => {
                // Nonce must follows in increasing order
                let (_, version) = storage.get_nonce_at_maximum_topoheight(key, topoheight).await?.ok_or_else(|| BlockchainError::AccountNotFound(key.as_address(storage.is_mainnet())))?;
                let stored_nonce = version.get_nonce();

                let mut entry = AccountEntry::new(stored_nonce);
                let valid = entry.insert_nonce_at_topoheight(nonce, topoheight);

                // Insert the entry into the cache before returning
                // So we don't have to search nonce again
                self.cache.insert(key.clone(), entry);

                if !valid {
                    return Ok(false);
                }
            }
        };

        Ok(true)
    }

    // Get the next nonce needed for the account
    pub fn get_new_nonce(&self, key: &PublicKey, mainnet: bool) -> Result<u64, BlockchainError> {
        let entry = self.cache.get(key).ok_or_else(|| BlockchainError::AccountNotFound(key.as_address(mainnet)))?;
        Ok(entry.expected_nonce)
    }
}