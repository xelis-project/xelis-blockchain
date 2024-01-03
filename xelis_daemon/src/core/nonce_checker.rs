use std::collections::HashMap;

use log::trace;
use xelis_common::crypto::key::PublicKey;

// A simple cache that checks if a nonce has already been used
// Stores the topoheight of the block that used the nonce
pub struct NonceChecker {
    cache: HashMap<PublicKey, HashMap<u64, u64>>,
}

impl NonceChecker {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new()
        }
    }

    // Key may be cloned on first entry
    // Returns false if nonce is already used
    pub fn use_nonce(&mut self, key: &PublicKey, nonce: u64, topoheight: u64) -> bool {
        trace!("use_nonce for {}: {} at topoheight {}", key, nonce, topoheight);

        match self.cache.get_mut(key) {
            Some(set) => {
                if set.contains_key(&nonce) {
                    return false;
                } else {
                    set.insert(nonce, topoheight);
                }
            },
            None => {
                let mut used_nonces = HashMap::new();
                used_nonces.insert(nonce, topoheight);
                self.cache.insert(key.clone(), used_nonces);
            }
        };

        true
    }
}