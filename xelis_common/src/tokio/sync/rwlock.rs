use std::{ops::{Deref, DerefMut}, time::Duration};
use tokio::{
    sync::{RwLock as InnerRwLock, RwLockReadGuard, RwLockWriteGuard},
    time::timeout
};

// Simple wrapper around RwLock
// to panic on a failed lock
pub struct RwLock<T: ?Sized> {
    inner: InnerRwLock<T>
}

impl<T: ?Sized> RwLock<T> {
    #[track_caller]
    pub fn new(value: T) -> Self
    where
        T: Sized,
    {
        Self {
            inner: InnerRwLock::new(value)
        }
    }

    pub async fn read(&self) -> RwLockReadGuard<'_, T> {
        timeout(Duration::from_secs(10), self.inner.read()).await
            .expect("RwLock read available")
    }

    pub async fn write(&self) -> RwLockWriteGuard<'_, T> {
        timeout(Duration::from_secs(10), self.inner.write()).await
            .expect("RwLock write available")
    }
} 

impl<T: ?Sized> AsRef<InnerRwLock<T>> for RwLock<T> {
    fn as_ref(&self) -> &InnerRwLock<T> {
        &self.inner
    }
}

impl<T: ?Sized> Deref for RwLock<T> {
    type Target = InnerRwLock<T>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}


impl<T: ?Sized> DerefMut for RwLock<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T: ?Sized> std::fmt::Debug for RwLock<T>
where
    T: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}