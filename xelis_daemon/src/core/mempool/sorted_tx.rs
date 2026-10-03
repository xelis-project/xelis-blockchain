use std::sync::Arc;
use xelis_common::{time::TimestampSeconds, transaction::Transaction};

/// A shared pending transaction with cached size, fee rates and arrival time.
/// Caching the serialized size avoids recomputing it during memory accounting.
#[derive(Clone, serde::Serialize)]
pub struct SortedTx {
    /// Transaction shared with callers and block-building code.
    pub(super) tx: Arc<Transaction>,
    /// Arrival timestamp in seconds, used to expire pending sender sequences.
    pub(super) first_seen: TimestampSeconds,
    /// Serialized size in bytes, excluding allocator and index overhead.
    pub(super) size: usize,
    /// Fee rate after subtracting extra fees and rounding size up to kilobytes.
    pub(super) fee_per_kb: u64,
    /// Fee-limit rate computed with the same extra-fee and size adjustments.
    pub(super) fee_limit_per_kb: u64,
}

impl SortedTx {
    /// Borrow the shared transaction without cloning it.
    #[inline(always)]
    pub fn get_tx(&self) -> &Arc<Transaction> {
        &self.tx
    }

    /// Return the transaction's declared total fee before extra-fee adjustments.
    #[inline(always)]
    pub fn get_fee(&self) -> u64 {
        self.tx.get_fee()
    }

    /// Return the cached fee rate used for fee ordering and eviction.
    #[inline(always)]
    pub fn get_fee_per_kb(&self) -> u64 {
        self.fee_per_kb
    }

    /// Return the cached fee-limit rate used when selecting transactions.
    #[inline(always)]
    pub fn get_fee_limit_per_kb(&self) -> u64 {
        self.fee_limit_per_kb
    }

    /// Return the cached serialized transaction size in bytes.
    #[inline(always)]
    pub fn get_size(&self) -> usize {
        self.size
    }

    /// Return the timestamp in seconds when this entry was inserted.
    #[inline(always)]
    pub fn get_first_seen(&self) -> TimestampSeconds {
        self.first_seen
    }

    /// Consume the metadata wrapper and return its shared transaction.
    #[inline(always)]
    pub fn consume(self) -> Arc<Transaction> {
        self.tx
    }
}

