/// This module contains the concurrency provider trait
/// It is simply used to pass the concurrency allowed for async operations.
/// It automatically to be Send + Sync to be used in async contexts and to be passed to providers that need it.
pub trait ConcurrencyProvider: Send + Sync {
    /// Returns the concurrency allowed for async operations.
    fn concurrency(&self) -> usize;
}