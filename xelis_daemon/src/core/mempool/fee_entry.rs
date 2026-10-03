use std::{cmp::Ordering, sync::Arc};
use xelis_common::crypto::Hash;

/// Entry ordered by ascending fee rate and then transaction hash.
/// The first entry identifies a cheapest transaction; the hash tie-breaker
/// allows equal-fee transactions to coexist in the ordered set.
pub(super) struct TxFeeEntry {
    /// Cached fee rate used as the primary ordering key.
    pub(super) fee_per_kb: u64,
    /// Transaction identity and deterministic tie-breaker for equal fee rates.
    pub(super) hash: Arc<Hash>,
}

impl PartialEq for TxFeeEntry {
    /// Compare both keys so equality agrees with the fee index ordering.
    fn eq(&self, other: &Self) -> bool {
        self.fee_per_kb == other.fee_per_kb && self.hash == other.hash
    }
}

impl Eq for TxFeeEntry {}

impl PartialOrd for TxFeeEntry {
    /// Use the total ordering defined by fee rate and transaction hash.
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TxFeeEntry {
    /// Order cheapest transactions first, breaking fee ties by hash.
    fn cmp(&self, other: &Self) -> Ordering {
        self.fee_per_kb.cmp(&other.fee_per_kb)
            .then_with(|| self.hash.cmp(&other.hash))
    }
}

