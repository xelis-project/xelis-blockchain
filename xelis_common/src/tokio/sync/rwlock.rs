use std::{
    future::Future,
    ops::{Deref, DerefMut},
    panic::Location,
    sync::{Arc, Mutex as StdMutex},
    time::Duration
};
use tokio::{
    sync::{
        RwLock as InnerRwLock,
        RwLockReadGuard as InnerRwLockReadGuard,
        RwLockWriteGuard as InnerRwLockWriteGuard,
    },
    time::timeout
};
use log::{debug, error};

// Simple wrapper around RwLock
// to panic on a failed lock and print all actual lock locations
pub struct RwLock<T: ?Sized> {
    init_location: &'static Location<'static>,
    active_write_location: Arc<StdMutex<Option<&'static Location<'static>>>>,
    active_read_locations: Arc<StdMutex<Vec<&'static Location<'static>>>>,
    inner: InnerRwLock<T>
}

impl<T: ?Sized> RwLock<T> {
    #[track_caller]
    pub fn new(value: T) -> Self
    where
        T: Sized,
    {
        Self {
            init_location: Location::caller(),
            active_write_location: Arc::new(StdMutex::new(None)),
            active_read_locations: Arc::new(StdMutex::new(Vec::new())),
            inner: InnerRwLock::new(value)
        }
    }

    fn show_locations(&self, location: &Location) {
        let mut msg = String::new();
        {
            let location = self.active_write_location.lock().expect("last write location");
            if let Some(location) = location.as_ref() {
                msg.push_str(&format!("\n- write guard at: {}", location));
            } else {
                msg.push_str("\n- no active write location");
            }
        }

        {
            let locations = self.active_read_locations.lock().expect("last read locations");
            for (i, location) in locations.iter().enumerate() {
                msg.push_str(&format!("\n- read guard #{} at: {}", i, location));
            }
        }

        error!("RwLock {} timed out at {}: {}", self.init_location, location, msg)
    }

    #[track_caller]
    pub fn read(&self) -> impl Future<Output = RwLockReadGuard<'_, T>> {
        let location = Location::caller();
        debug!("RwLock {} trying to read at {}", self.init_location, location);
        async {
            loop {
                match timeout(Duration::from_secs(10), self.inner.read()).await {
                    Ok(guard) => {
                        let mut locations = self.active_read_locations.lock().expect("active read locations");
                        locations.push(location);
        
                        return RwLockReadGuard {
                            inner: guard,
                            locations: self.active_read_locations.clone(),
                            location,
                        };
                    }
                    Err(_) => self.show_locations(location)
                };
            }
        }
    }

    #[track_caller]
    pub fn write(&self) -> impl Future<Output = RwLockWriteGuard<'_, T>> {
        let location = Location::caller();
        debug!("RwLock {} trying to write at {}", self.init_location, location);
        async {
            loop {
                match timeout(Duration::from_secs(10), self.inner.write()).await {
                    Ok(guard) => {
                        *self.active_write_location.lock().expect("last write location") = Some(location);
                        return RwLockWriteGuard {
                            inner: guard,
                            active_location: self.active_write_location.clone(),
                        };
                    }
                    Err(_) => self.show_locations(location)
                };
            }
        }
    }
}

#[derive(Debug)]
pub struct RwLockReadGuard<'a, T: ?Sized> {
    inner: InnerRwLockReadGuard<'a, T>,
    locations: Arc<StdMutex<Vec<&'static Location<'static>>>>,
    location: &'static Location<'static>,
}

impl<'a, T: ?Sized> Drop for RwLockReadGuard<'a, T> {
    fn drop(&mut self) {
        // We don't use a HashSet in case of multi threading where we would lock at same location
        debug!("Dropping RwLockReadGuard at {}", self.location);
        let mut locations = self.locations.lock().expect("locations");
        let index = locations.iter()
            .position(|v| *v == self.location)
            .expect("location position");

        locations.remove(index);
    }
}

impl<'a, T: ?Sized> Deref for RwLockReadGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[derive(Debug)]
pub struct RwLockWriteGuard<'a, T: ?Sized> {
    inner: InnerRwLockWriteGuard<'a, T>,
    active_location: Arc<StdMutex<Option<&'static Location<'static>>>>,
}

impl<'a, T: ?Sized> Drop for RwLockWriteGuard<'a, T> {
    fn drop(&mut self) {
        let active_location = self.active_location.lock()
            .expect("active write location")
            .take()
            .expect("active write location should be set");

        debug!("Dropping RwLockWriteGuard at {}", active_location);
    }
}

impl<'a, T: ?Sized> Deref for RwLockWriteGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'a, T: ?Sized> DerefMut for RwLockWriteGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rwlock() {
        let lock = RwLock::new(42);
        {
            let read_guard = lock.read().await;
            {
                let locations = lock.active_read_locations.lock().unwrap();
                assert_eq!(locations.len(), 1);
            }
            assert_eq!(*read_guard, 42);
        }

        {
            let locations = lock.active_read_locations.lock().unwrap();
            assert!(locations.is_empty());
        }

        {
            let mut write_guard = lock.write().await;
            {
                let location = lock.active_write_location.lock().unwrap();
                assert!(location.is_some());
            }

            *write_guard += 1;
        }
        {
            let read_guard = lock.read().await;
            assert_eq!(*read_guard, 43);
        }
    }
}