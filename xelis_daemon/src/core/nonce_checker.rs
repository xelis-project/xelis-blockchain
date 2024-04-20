use std::collections::HashMap;

use indexmap::IndexMap;
use log::trace;
use xelis_common::crypto::PublicKey;

use super::{storage::Storage, error::BlockchainError};

struct AccountEntry {
    expected_nonce: u64,
    used_nonces: IndexMap<u64, u64>
}

impl AccountEntry {
    pub fn new(nonce: u64) -> Self {
        Self {
            expected_nonce: nonce,
            used_nonces: IndexMap::new()
        }
    }

    pub fn contains_nonce(&self, nonce: &u64) -> bool {
        self.used_nonces.contains_key(nonce)
    }

    pub fn insert_nonce_at_topoheight(&mut self, nonce: u64, topoheight: u64) -> bool {
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

    // Key may be cloned on first entry
    // Returns false if nonce is already used
    pub async fn use_nonce<S: Storage>(&mut self, storage: &S, key: &PublicKey, nonce: u64, topoheight: u64) -> Result<bool, BlockchainError> {
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