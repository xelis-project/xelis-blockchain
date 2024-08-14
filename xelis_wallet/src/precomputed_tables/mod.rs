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

// Allows to be used in several wallets at the same time
pub type PrecomputedTablesShared = Arc<ecdlp::ECDLPTables<PRECOMPUTED_TABLES_L1>>;