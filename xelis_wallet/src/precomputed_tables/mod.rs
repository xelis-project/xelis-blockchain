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

use std::sync::Arc;
use xelis_common::crypto::ecdlp;

// ECDLP Tables L1 size
// L1 at 26 is around ~330 MB of RAM and support up to 2^48 values
pub const PRECOMPUTED_TABLES_L1: usize = 26;

// Allows to be used in several wallets at the same time
pub type PrecomputedTablesShared = Arc<ecdlp::ECDLPTables<PRECOMPUTED_TABLES_L1>>;