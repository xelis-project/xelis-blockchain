use std::ops::{Deref, DerefMut};
use xelis_common::tokio::{
    sync::{RwLock, RwLockReadGuard, Mutex, RwLockWriteGuard}
};
use crate::core::{
    storage::Storage,
    error::BlockchainError,
    storage::snapshot::Snapshot,
};

pub enum StorageHolder<'a, S: Storage> {
    Storage(&'a RwLock<S>),
    Snapshot(&'a SnapshotWrapper<'a, S>),
}

pub enum StorageReadGuard<'a, S: Storage> {
    Storage(RwLockReadGuard<'a, S>),
    Snapshot(SnapshotGuard<'a, S>),
}

impl<S: Storage> Deref for StorageReadGuard<'_, S> {
    type Target = S;

    #[inline]
    fn deref(&self) -> &Self::Target {
        match self {
            StorageReadGuard::Storage(guard) => &*guard,
            StorageReadGuard::Snapshot(guard) => &*guard,
        }
    }
}

pub enum StorageWriteGuard<'a, S: Storage> {
    Storage(RwLockWriteGuard<'a, S>),
    Snapshot(SnapshotGuard<'a, S>),
}

impl<'a, S: Storage> StorageWriteGuard<'a, S> {
    #[inline]
    pub fn downgrade(self) -> StorageReadGuard<'a, S> {
        match self {
            StorageWriteGuard::Storage(guard) => {
                StorageReadGuard::Storage(RwLockWriteGuard::downgrade(guard))
            },
            StorageWriteGuard::Snapshot(guard) => {
                StorageReadGuard::Snapshot(guard)
            }
        }
    }
}

impl<S: Storage> Deref for StorageWriteGuard<'_, S> {
    type Target = S;

    #[inline]
    fn deref(&self) -> &Self::Target {
        match self {
            StorageWriteGuard::Storage(guard) => &*guard,
            StorageWriteGuard::Snapshot(guard) => &*guard,
        }
    }
}

impl<S: Storage> DerefMut for StorageWriteGuard<'_, S> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            StorageWriteGuard::Storage(guard) => &mut *guard,
            StorageWriteGuard::Snapshot(guard) => &mut *guard,
        }
    }
}

impl<'a, S: Storage> StorageHolder<'a, S> {
    #[inline]
    pub async fn read(&self) -> Result<StorageReadGuard<'_, S>, BlockchainError> {
        match self {
            StorageHolder::Storage(storage) => {
                let guard = storage.read().await;
                Ok(StorageReadGuard::Storage(guard))
            },
            StorageHolder::Snapshot(wrapper) => {
                let guard = wrapper.lock().await?;
                Ok(StorageReadGuard::Snapshot(guard))
            }
        }
    }

    #[inline]
    pub async fn write(&self) -> Result<StorageWriteGuard<'_, S>, BlockchainError> {
        match self {
            StorageHolder::Storage(storage) => {
                let guard = storage.write().await;
                Ok(StorageWriteGuard::Storage(guard))
            },
            StorageHolder::Snapshot(wrapper) => {
                let guard = wrapper.lock().await?;
                Ok(StorageWriteGuard::Snapshot(guard))
            }
        }
    }
}

/// A wrapper around Storage that automatically manages snapshot lifecycle
/// The snapshot is kept internally and swapped in/out on lock/unlock
pub struct SnapshotWrapper<'a, S: Storage> {
    storage: &'a RwLock<S>,
    snapshot: Mutex<Option<Snapshot<S::Column>>>,
}

impl<'a, S: Storage> SnapshotWrapper<'a, S> {
    #[inline]
    pub fn new(storage: &'a RwLock<S>) -> Self {
        Self {
            storage,
            snapshot: Mutex::new(None),
        }
    }

    /// Acquire a write lock and swap in the snapshot
    pub async fn lock(&self) -> Result<SnapshotGuard<'_, S>, BlockchainError> {
        let mut guard = self.storage.write().await;
        let mut snapshot_guard = self.snapshot.lock().await;
        match snapshot_guard.take() {
            Some(previous) => {
                *snapshot_guard = guard.swap_snapshot(Some(previous))?;
            },
            None => {
                guard.start_snapshot().await?;
            }
        }

        Ok(SnapshotGuard {
            snapshot: &self.snapshot,
            guard,
        })
    }
}

pub struct SnapshotGuard<'a, S: Storage> {
    snapshot: &'a Mutex<Option<Snapshot<S::Column>>>,
    guard: RwLockWriteGuard<'a, S>,
}

impl<S: Storage> Deref for SnapshotGuard<'_, S> {
    type Target = S;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl<S: Storage> DerefMut for SnapshotGuard<'_, S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

impl<S: Storage> Drop for SnapshotGuard<'_, S> {
    fn drop(&mut self) {
        // SAFETY: Because we are holding the RwLockWriteGuard, no other thread can access the snapshot at this time

        let mut snapshot_guard = self.snapshot.try_lock()
            .expect("Failed to lock snapshot mutex on drop");
        *snapshot_guard = self.guard.swap_snapshot(snapshot_guard.take())
            .expect("Failed to swap snapshot on drop");
    }
}