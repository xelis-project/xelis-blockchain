use std::{
    collections::HashMap,
    sync::{Arc, Weak, Mutex, atomic::{AtomicU64, Ordering as AtomicOrdering}},
};
use tokio::sync::{Semaphore, OwnedSemaphorePermit};
use xelis_common::crypto::PublicKey;

/// Registry shared by admission and backend invalidation.
/// Weak entries avoid retaining idle senders; leases keep holders and waiters alive.
pub(super) type SenderLocks = Arc<Mutex<HashMap<PublicKey, Weak<SenderLock>>>>;

/// Admission gate and cache revision shared by all active requests for one sender.
pub(super) struct SenderLock {
    /// A single permit serializes verification and commit for this sender.
    pub(super) semaphore: Arc<Semaphore>,
    /// Incremented under backend write access whenever this sender cache changes.
    /// Backend guards synchronize snapshot reads and writes, so relaxed atomic
    /// access is sufficient for this counter.
    pub(super) revision: AtomicU64,
}

/// Retains the unique sender gate while an admission holds or awaits its permit.
/// The last lease removes the weak registry entry, including on cancellation.
pub(super) struct SenderLease {
    /// Public key identifying the sender whose gate is retained.
    pub(super) source: PublicKey,
    /// Strong gate reference, taken during drop while the registry is locked.
    pub(super) lock: Option<Arc<SenderLock>>,
    /// Registry from which the last lease removes its sender entry.
    pub(super) registry: SenderLocks,
}

impl SenderLease {
    /// Borrow the retained gate while this lease is live.
    pub(super) fn lock(&self) -> &SenderLock {
        self.lock.as_ref().expect("sender lease is live")
    }
}

impl Drop for SenderLease {
    /// Remove the registry entry when releasing the last active lease.
    /// Release the strong gate reference before unlocking, so concurrent lease
    /// drops and new lookups observe the correct ownership count.
    fn drop(&mut self) {
        let mut registry = self.registry.lock().expect("sender lock registry poisoned");
        if let Some(lock) = self.lock.take() {
            if Arc::strong_count(&lock) == 1 {
                registry.remove(&self.source);
            }
            // Release our reference before unlocking the registry: concurrent
            // lease drops must see the updated reference count.
            drop(lock);
        }
    }
}

/// Owned sender permit together with the revision used for verification.
/// Its lease survives cache eviction so a new admission cannot obtain a
/// second semaphore for the same sender while this verification is active.
pub(super) struct SenderVerification {
    /// Owned permit, declared first so it is released before dropping the lease.
    pub(super) _permit: OwnedSemaphorePermit,
    /// Keeps the sender identity and semaphore registration alive.
    pub(super) lease: SenderLease,
    /// Cache revision captured under the same backend guard as the sender snapshot.
    pub(super) revision: u64,
}

impl SenderVerification {
    /// Return the expected revision for this sender cache, which must match the backend snapshot.
    pub fn revision_expected(&self) -> u64 {
        self.lease.lock().revision.load(AtomicOrdering::Relaxed)
    }

    /// Check whether the sender cache still matches the verification snapshot.
    /// Call only with a backend guard held, so a concurrent eviction cannot
    /// change the revision between this check and reading or committing state.
    pub(super) fn is_current(&self) -> bool {
        self.revision_expected() == self.revision
    }
}

