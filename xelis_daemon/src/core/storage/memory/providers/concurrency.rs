use crate::core::storage::ConcurrencyProvider;
use super::super::MemoryStorage;

impl ConcurrencyProvider for MemoryStorage {
    fn concurrency(&self) -> usize {
        self.concurrency
    }
}
