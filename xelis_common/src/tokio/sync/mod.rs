#[cfg(all(
    feature = "tokio",
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown",
))]
pub use tokio_with_wasm::sync::*;

#[cfg(all(
    feature = "tokio",
    not(all(
        target_arch = "wasm32",
        target_vendor = "unknown",
        target_os = "unknown",
    )),
    not(feature = "deadlock-detection")
))]
pub use tokio::sync::*;

#[cfg(feature = "deadlock-detection")]
pub use tokio::sync::{
    Semaphore,
    mpsc,
    broadcast,
    oneshot,
    futures,
    watch,
    AcquireError,
    TryAcquireError,
};

#[cfg(any(test, feature = "deadlock-detection"))]
mod rwlock;

#[cfg(feature = "deadlock-detection")]
pub use rwlock::*;

#[cfg(any(test, feature = "deadlock-detection"))]
mod mutex;
#[cfg(feature = "deadlock-detection")]
pub use mutex::*;