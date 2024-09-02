use std::net::IpAddr;

use log::info;
use sled::{Config, Db, Mode, Tree};
use xelis_common::serializer::{ReaderError, Serializer};
use thiserror::Error;

use super::peer_list::PeerListEntry;

#[derive(Debug, Error)]
pub enum DiskError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Sled error: {0}")]
    Sled(#[from] sled::Error),
    #[error("Not found")]
    NotFound,
    #[error("Read error: {0}")]
    ReaderError(#[from] ReaderError),
}

// Previously, we were caching everything in the memory directly.
// But over time, the memory usage will grow and be a problem for low devices.
// DiskCache is a disk-based cache that stores the peerlist in the disk.
// It uses sled as the underlying storage engine.
// This means IO operations instead of memory operations.
// Performance versus memory usage tradeoff.
pub struct DiskCache {
    // All known peers
    peerlist: Tree,
    // DB to use
    db: Db,
}

impl DiskCache {
    // Create a new disk cache
    pub fn new(filename: String) -> Result<Self, DiskError> {
        let config = Config::new().temporary(false)
            .path(filename)
            .cache_capacity(16 * 1024)
            .segment_size(256)
            .mode(Mode::LowSpace);

        let db = config.open()?;

        Ok(Self {
            peerlist: db.open_tree("peerlist")?,
            db,
        })
    }

    // Check if a peerlist entry is present in DB
    pub fn has_peerlist_entry(&self, peer: &IpAddr) -> Result<bool, DiskError> {
        Ok(self.peerlist.contains_key(peer.to_bytes())?)
    }

    // Set a peer state using its IP address
    pub fn set_peerlist_entry(&self, peer: &IpAddr, entry: PeerListEntry) -> Result<(), DiskError> {
        self.peerlist.insert(peer.to_bytes(), entry.to_bytes())?;
        Ok(())
    }

    // Get a PeerListEntry using its IP address
    pub fn get_peerlist_entry(&self, peer: &IpAddr) -> Result<PeerListEntry, DiskError> {
        let v = self.peerlist.get(peer.to_bytes())?
            .map(|v| PeerListEntry::from_bytes(&v))
            .ok_or(DiskError::NotFound)??;

        Ok(v)
    }

    // Get all entries of peerlist
    // Returns an iterator to lazily load peers
    pub fn get_peerlist_entries(&self) -> impl Iterator<Item = Result<(IpAddr, PeerListEntry), DiskError>> {
        self.peerlist.iter()
            .map(|r| {
                let (k, v) = r?;
                let ip = IpAddr::from_bytes(&k)?;
                let entry = PeerListEntry::from_bytes(&v)?;
                Ok((ip, entry))
            })
    }

    // Remove a peer from the peerlist
    pub fn remove_peerlist_entry(&self, peer: &IpAddr) -> Result<(), DiskError> {
        self.peerlist.remove(peer.to_bytes())?;
        Ok(())
    }

    // Clear the peerlist
    pub async fn clear_peerlist(&self) -> Result<(), DiskError> {
        self.peerlist.clear()?;
        self.db.flush_async().await?;
        Ok(())
    }

    // Flush the cache to disk
    pub async fn flush(&self) -> Result<(), DiskError> {
        info!("Flushing Disk Cache");
        self.db.flush_async().await?;
        Ok(())
    }
}