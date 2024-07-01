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

use log::debug;
use xelis_common::crypto::ecdlp;

// This is a 32 bytes aligned struct
// It is necessary for the precomputed tables points
#[derive(bytemuck::Pod, bytemuck::Zeroable, Copy, Clone)]
#[repr(C, align(32))]
struct Bytes32Alignment([u8; 32]);

enum Inner {
    Allocated(Vec<Bytes32Alignment>),
    Borrowed(&'static [u8]),
}

impl Inner {
    fn as_slice(&self, count: usize) -> &[u8] {
        match self {
            Inner::Allocated(v) => &bytemuck::cast_slice(v.as_slice())[..count],
            Inner::Borrowed(v) => v
        }
    }

    fn as_mut_slice(&mut self, count: usize) -> &mut [u8] {
        match self {
            Inner::Allocated(v) => &mut bytemuck::cast_slice_mut(v.as_mut_slice())[..count],
            Inner::Borrowed(_) => panic!("Cannot get mutable reference to borrowed data"),
        }
    }
}


pub struct PrecomputedTables {
    inner: Inner,
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
            inner: Inner::Allocated(bytes),
            l1,
            bytes_count
        }
    }

    pub fn with_bytes(bytes: &'static [u8], l1: usize) -> Self {
        Self {
            inner: Inner::Borrowed(bytes),
            l1,
            bytes_count: bytes.len()
        }
    }

    pub fn get<'a>(&'a self) -> &'a [u8] {
      self.inner.as_slice(self.bytes_count)
    }

    pub fn get_mut<'a>(&'a mut self) -> &'a mut [u8] {
        self.inner.as_mut_slice(self.bytes_count)
    }

    pub fn l1(&self) -> usize {
        self.l1
    }

    pub fn bytes_count(&self) -> usize {
        self.bytes_count
    }
}
