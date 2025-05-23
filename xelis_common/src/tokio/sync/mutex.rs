use std::{ops::{Deref, DerefMut}, time::Duration};
use tokio::{
    sync::{Mutex as InnerMutex, MutexGuard},
    time::timeout
};

pub struct Mutex<T: ?Sized> {
    inner: InnerMutex<T>
}

impl<T: ?Sized> Mutex<T> {
    #[track_caller]
    pub fn new(t: T) -> Self
    where
        T: Sized,
    {
        Self {
            inner: InnerMutex::new(t)
        }
    }

    pub async fn lock(&self) -> MutexGuard<'_, T> {
        timeout(Duration::from_secs(10), self.inner.lock()).await
            .expect("Mutex lock available")
    }
}


impl<T: ?Sized> AsRef<InnerMutex<T>> for Mutex<T> {
    fn as_ref(&self) -> &InnerMutex<T> {
        &self.inner
    }
}

impl<T: ?Sized> Deref for Mutex<T> {
    type Target = InnerMutex<T>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}


impl<T: ?Sized> DerefMut for Mutex<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T: ?Sized> std::fmt::Debug for Mutex<T>
where
    T: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}