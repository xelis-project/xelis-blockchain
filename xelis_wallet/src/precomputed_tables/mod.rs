use std::sync::{Arc, RwLock};
use xelis_common::crypto::ecdlp;

#[cfg(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
mod web;

#[cfg(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
pub use web::*;

#[cfg(not(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
)))]
mod native;

#[cfg(not(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
)))]
pub use native::*;

// ECDLP Tables L1 size
pub const L1_LOW: usize = 13;

// ECDLP Tables L1 size
pub const L1_MEDIUM: usize = 18;

// ECDLP Tables L1 size
// L1 at 26 is around ~330 MB of RAM and support up to 2^48 values
pub const L1_FULL: usize = 26;


// Allows to be used in several wallets at the same time
pub type PrecomputedTablesShared = Arc<RwLock<ecdlp::ECDLPTables>>;
