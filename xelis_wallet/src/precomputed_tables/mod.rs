#[cfg(any(
    all(
        target_arch = "wasm32",
        target_vendor = "unknown",
        target_os = "unknown"
    ),
    test
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

use log::debug;
use xelis_common::crypto::ecdlp;

// This is a 32 bytes aligned struct
// It is necessary for the precomputed tables points
#[derive(bytemuck::Pod, bytemuck::Zeroable, Copy, Clone)]
#[repr(C, align(32))]
struct Bytes32Alignment([u8; 32]);

pub struct PrecomputedTables {
    bytes: Vec<Bytes32Alignment>,
    l1: usize,
    bytes_count: usize,
}

// Allows to be used in several wallets at the same time
pub type PrecomputedTablesShared = Arc<PrecomputedTables>;

impl PrecomputedTables {
    pub fn new(l1: usize) -> Self {
        let bytes_count = ecdlp::table_generation::table_file_len(l1);
        debug!("Precomputed tables size: {} bytes", bytes_count);
        let mut n = bytes_count / 32;
        if bytes_count % 32 != 0 {
            n += 1;
        }

        let bytes = vec![Bytes32Alignment([0; 32]); n];

        Self {
            bytes,
            l1,
            bytes_count
        }
    }

    pub fn get<'a>(&'a self) -> &'a [u8] {
       &bytemuck::cast_slice(self.bytes.as_slice())[..self.bytes_count]
    }

    pub fn get_mut<'a>(&'a mut self) -> &'a mut [u8] {
        &mut bytemuck::cast_slice_mut(self.bytes.as_mut_slice())[..self.bytes_count]
    }

    pub fn l1(&self) -> usize {
        self.l1
    }

    pub fn bytes_count(&self) -> usize {
        self.bytes_count
    }
}
