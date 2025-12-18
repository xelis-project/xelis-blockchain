use std::{
    future::Future,
    ops::{Deref, DerefMut},
    panic::Location,
    sync::{atomic::{AtomicU64, Ordering}, Arc, Mutex as StdMutex},
    time::Duration
};
use crate::time::Instant;
use tokio::{
    pin,
    sync::{
        RwLock as InnerRwLock,
        RwLockReadGuard as InnerRwLockReadGuard,
        RwLockWriteGuard as InnerRwLockWriteGuard,
    },
    time::interval
};
use log::{debug, error, log, Level};

// Simple wrapper around RwLock
// to panic on a failed lock and print all actual lock locations
pub struct RwLock<T: ?Sized> {
    init_location: &'static Location<'static>,
    active_write_location: Arc<StdMutex<Option<(&'static Location<'static>, Instant)>>>,
    active_read_locations: Arc<StdMutex<Vec<(&'static Location<'static>, Instant)>>>,
    read_guards: Arc<AtomicU64>,
    inner: InnerRwLock<T>,
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
            read_guards: Arc::new(AtomicU64::new(0)),
            inner: InnerRwLock::new(value),
        }
    }

    fn show_locations(&self, location: &Location, write: bool) {
        let mut msg = String::new();
        {
            let location = self.active_write_location.lock().expect("last write location");
            if let Some((location, start)) = location.as_ref() {
                msg.push_str(&format!("\n- write guard at: {} since {:?}", location, start.elapsed()));
            } else {
                msg.push_str("\n- no active write location");
            }
        }

        {
            let locations = self.active_read_locations.lock().expect("last read locations");
            for (i, (location, start)) in locations.iter().enumerate() {
                msg.push_str(&format!("\n- read guard #{} at: {} since {:?}", i, location, start.elapsed()));
            }
        }

        let guards = self.read_guards.load(Ordering::SeqCst);
        error!("RwLock {} (write = {}) (active guards = {}) timed out at {}: {}", self.init_location, write, guards, location, msg)
    }

    #[track_caller]
    pub fn read(&self) -> impl Future<Output = RwLockReadGuard<'_, T>> {
        let location = Location::caller();
        debug!("RwLock {} trying to read at {}", self.init_location, location);

        async move {
            let mut interval = interval(Duration::from_secs(10));
            // First tick is instant
            interval.tick().await;

            let future = self.inner.read();
            pin!(future);

            let mut show = true;
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if show {
                            self.show_locations(location, false);
                            show = false;
                        }
                    }
                    guard = &mut future => {
                        let level = if !show {
                            Level::Warn
                        } else {
                            Level::Debug
                        };
                        log!(level, "RwLock {} read guard acquired at {}", self.init_location, location);

                        let mut locations = self.active_read_locations.lock().expect("active read locations");
                        locations.push((location, Instant::now()));

                        self.read_guards.fetch_add(1, Ordering::SeqCst);

                        return RwLockReadGuard {
                            init_location: self.init_location,
                            inner: Some(guard),
                            locations: self.active_read_locations.clone(),
                            location,
                            read_guards: self.read_guards.clone(),
                        };
                    }
                }
            }
        }
    }

    #[track_caller]
    pub fn write(&self) -> impl Future<Output = RwLockWriteGuard<'_, T>> {
        let location = Location::caller();
        debug!("RwLock {} trying to write at {}", self.init_location, location);

        async move {
            let mut interval = interval(Duration::from_secs(10));
            // First tick is instant
            interval.tick().await;

            let future = self.inner.write();
            pin!(future);

            let mut show = true;
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if !show {
                            self.show_locations(location, true);
                            show = false;
                        }
                    }
                    guard = &mut future => {
                        // It was maybe deadlocked, show it in warn
                        let level = if !show {
                            Level::Warn
                        } else {
                            Level::Debug
                        };
                        log!(level, "RwLock {} write guard acquired at {}", self.init_location, location);
                        *self.active_write_location.lock().expect("last write location") = Some((location, Instant::now()));
                        return RwLockWriteGuard {
                            init_location: self.init_location,
                            inner: Some(guard),
                            active_location: self.active_write_location.clone(),
                        };
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct RwLockReadGuard<'a, T: ?Sized> {
    init_location: &'static Location<'static>,
    inner: Option<InnerRwLockReadGuard<'a, T>>,
    locations: Arc<StdMutex<Vec<(&'static Location<'static>, Instant)>>>,
    location: &'static Location<'static>,
    read_guards: Arc<AtomicU64>,
}

impl<'a, T: ?Sized> Drop for RwLockReadGuard<'a, T> {
    fn drop(&mut self) {
        {
            let guard = self.inner.take().expect("drop");
            drop(guard);
        }

        // We don't use a HashSet in case of multi threading where we would lock at same location
        let mut locations = self.locations.lock()
            .expect("locations");

        let index = locations.iter()
            .position(|(v, _)| *v == self.location)
            .expect("location position");
    
        let (_, lifetime) = locations.remove(index);
        let guards = self.read_guards.fetch_sub(1, Ordering::SeqCst);
        debug!("Dropping {} RwLockReadGuard at {} after {:?} (guards = {})", self.init_location, self.location, lifetime.elapsed(), guards);
    }
}

impl<'a, T: ?Sized> Deref for RwLockReadGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner.as_ref().expect("not dropped")
    }
}

#[derive(Debug)]
pub struct RwLockWriteGuard<'a, T: ?Sized> {
    init_location: &'static Location<'static>,
    inner: Option<InnerRwLockWriteGuard<'a, T>>,
    active_location: Arc<StdMutex<Option<(&'static Location<'static>, Instant)>>>,
}

impl<'a, T: ?Sized> Drop for RwLockWriteGuard<'a, T> {
    fn drop(&mut self) {
        {
            let guard = self.inner.take().expect("drop");
            drop(guard);
        }

        let (active_location, lifetime) = self.active_location.lock()
            .expect("active write location")
            .take()
            .expect("active write location should be set");

        debug!("Dropping {} RwLockWriteGuard at {} after {:?}", self.init_location, active_location, lifetime.elapsed());
    }
}

impl<'a, T: ?Sized> Deref for RwLockWriteGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner.as_ref().expect("not dropped")
    }
}

impl<'a, T: ?Sized> DerefMut for RwLockWriteGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner.as_mut()
            .expect("not dropped")
    }
}

// impl<T: ?Sized> AsRef<InnerRwLock<T>> for RwLock<T> {
//     fn as_ref(&self) -> &InnerRwLock<T> {
//         &self.inner
//     }
// }

// impl<T: ?Sized> Deref for RwLock<T> {
//     type Target = InnerRwLock<T>;

//     fn deref(&self) -> &Self::Target {
//         &self.inner
//     }
// }

// impl<T: ?Sized> DerefMut for RwLock<T> {
//     fn deref_mut(&mut self) -> &mut Self::Target {
//         &mut self.inner
//     }
// }

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