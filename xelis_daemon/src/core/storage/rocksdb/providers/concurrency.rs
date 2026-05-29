use crate::core::storage::{ConcurrencyProvider, RocksStorage};

impl ConcurrencyProvider for RocksStorage {
    fn concurrency(&self) -> usize {
        self.concurrency
    }
}