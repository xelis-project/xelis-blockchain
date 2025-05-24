use std::{
    future::Future,
    ops::{Deref, DerefMut},
    panic::Location,
    sync::Mutex as StdMutex,
    time::Duration
};
use tokio::{
    sync::{Mutex as InnerMutex, MutexGuard},
    time::timeout
};
use log::error;

pub struct Mutex<T: ?Sized> {
    init_location: &'static Location<'static>,
    last_location: StdMutex<Option<&'static Location<'static>>>,
    inner: InnerMutex<T>,
}

impl<T: ?Sized> Mutex<T> {
    #[track_caller]
    pub fn new(t: T) -> Self
    where
        T: Sized,
    {
        Self {
            init_location: Location::caller(),
            last_location: StdMutex::new(None),
            inner: InnerMutex::new(t)
        }
    }

    #[track_caller]
    pub fn lock(&self) -> impl Future<Output = MutexGuard<'_, T>> {
        let location = Location::caller();
        async move {
            loop {
                match timeout(Duration::from_secs(10), self.inner.lock()).await {
                    Ok(guard) => {
                        *self.last_location.lock().expect("last lock location") = Some(location);
                        return guard;
                    }
                    Err(_) => {
                        let last = self.last_location.lock().expect("last lock location");
                        let mut msg = format!("Mutex at {} failed locking at {}.", self.init_location, location);
                        match *last {
                            Some(last) => {
                                msg.push_str(&format!("\n- Last successful lock at: {}", last));
                            }
                            None => {}
                        }
                        error!("{}", msg);
                    }
                };
            }
        }
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