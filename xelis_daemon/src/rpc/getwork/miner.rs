use std::{fmt, sync::Arc};

use indexmap::IndexSet;
use xelis_common::{
    crypto::{Hash, PublicKey},
    time::{get_current_time_in_millis, TimestampMillis}
};

pub struct Miner {
    // Used to display correctly its address
    mainnet: bool,
    // timestamp of first connection
    first_seen: TimestampMillis,
    // public key of account (address)
    key: PublicKey,
    // worker name
    name: String,
    // blocks accepted by us since he is connected
    blocks_accepted: IndexSet<Arc<Hash>>,
    // blocks rejected since he is connected
    blocks_rejected: usize,
    // timestamp of the last invalid block received
    last_invalid_block: TimestampMillis
}

impl Miner {
    pub fn new(mainnet: bool, key: PublicKey, name: String) -> Self {
        Self {
            mainnet,
            first_seen: get_current_time_in_millis(),
            key,
            name,
            blocks_accepted: IndexSet::new(),
            blocks_rejected: 0,
            last_invalid_block: 0
        }
    }

    pub fn first_seen(&self) -> u64 {
        self.first_seen
    }

    pub fn get_public_key(&self) -> &PublicKey {
        &self.key
    }

    pub fn get_name(&self) -> &String {
        &self.name
    }

    pub fn get_blocks_accepted(&self) -> usize {
        self.blocks_accepted.len()
    }

    pub fn add_new_accepted_block(&mut self, hash: Arc<Hash>) {
        self.blocks_accepted.insert(hash);
    }

    pub fn mark_rejected_block(&mut self) {
        self.blocks_rejected += 1;
        self.last_invalid_block += get_current_time_in_millis();
    }
}

impl fmt::Display for Miner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let valid_blocks = self.blocks_accepted.iter()
            .take(8)
            .map(|h| h.to_string())
            .collect::<Vec<_>>()
            .join(",");

        write!(f, "Miner[address={}, name={}, accepted={} ({}), rejected={}]", self.key.as_address(self.mainnet), self.name, self.blocks_accepted.len(), valid_blocks, self.blocks_rejected)
    }
}
