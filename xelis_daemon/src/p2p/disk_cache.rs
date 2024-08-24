use std::net::IpAddr;

use log::info;
use sled::{Config, Db, Mode, Tree};
use xelis_common::serializer::{ReaderError, Serializer};
use thiserror::Error;

use super::peer_list::StoredPeer;

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

pub struct DiskCache {
    // All known peers
    peerlist: Tree,
    // DB to use
    db: Db,
}

impl DiskCache {
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

    pub fn has_peer(&self, peer: &IpAddr) -> Result<bool, DiskError> {
        Ok(self.peerlist.contains_key(peer.to_bytes())?)
    }

    pub fn set_stored_peer(&self, peer: &IpAddr, stored: StoredPeer) -> Result<(), DiskError> {
        self.peerlist.insert(peer.to_bytes(), stored.to_bytes())?;
        Ok(())
    }

    pub fn get_stored_peer(&self, peer: &IpAddr) -> Result<StoredPeer, DiskError> {
        let v = self.peerlist.get(peer.to_bytes())?
            .map(|v| StoredPeer::from_bytes(&v))
            .ok_or(DiskError::NotFound)??;

        Ok(v)
    }

    pub fn get_stored_peers(&self) -> impl Iterator<Item = Result<(IpAddr, StoredPeer), DiskError>> {
        self.peerlist.iter()
            .map(|r| {
                let (k, v) = r?;
                let ip = IpAddr::from_bytes(&k)?;
                let stored = StoredPeer::from_bytes(&v)?;
                Ok((ip, stored))
            })
    }

    pub fn remove_peer(&self, peer: &IpAddr) -> Result<(), DiskError> {
        self.peerlist.remove(peer.to_bytes())?;
        Ok(())
    }

    pub async fn clear_peerlist(&self) -> Result<(), DiskError> {
        self.peerlist.clear()?;
        self.db.flush_async().await?;
        Ok(())
    }

    pub async fn flush(&self) -> Result<(), DiskError> {
        info!("Flushing Disk Cache");
        self.db.flush_async().await?;
        Ok(())
    }
}