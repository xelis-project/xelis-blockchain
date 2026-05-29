use crate::core::storage::{ConcurrencyProvider, SledStorage};

impl ConcurrencyProvider for SledStorage {
    fn concurrency(&self) -> usize {
        self.concurrency
    }
}