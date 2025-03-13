#[cfg(feature = "tokio")]
mod thread_pool;

use std::future::Future;
use log::trace;


#[cfg(feature = "tokio")]
pub use thread_pool::ThreadPool;

#[cfg(all(
    feature = "tokio",
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
pub use tokio_with_wasm::*;

#[cfg(all(
    feature = "tokio",
    not(all(
        target_arch = "wasm32",
        target_vendor = "unknown",
        target_os = "unknown"
    ))
))]
pub use tokio::*;

#[cfg(feature = "tokio")]
use runtime::{Handle, RuntimeFlavor};

// Spawn a new task with a name
// If the tokio_unstable feature is enabled, the task will be named
#[inline(always)]
#[cfg(all(
    feature = "tokio",
    not(all(
        target_arch = "wasm32",
        target_vendor = "unknown",
        target_os = "unknown"
    ))
))]
#[track_caller]
pub fn spawn_task<F, S: Into<String>>(name: S, future: F) -> task::JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let name_str = name.into();
    trace!("Spawning task: {}", name_str);
    #[cfg(feature = "tracing")]
    {
        let name = name_str.as_str();
        task::Builder::new().name(name).spawn(future).expect(name)
    }
    #[cfg(not(feature = "tracing"))]
    {
        tokio::spawn(future)
    }
}

// Spawn a new task with a name
// Send trait is not required for wasm32
#[cfg(all(
    feature = "tokio",
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
pub fn spawn_task<F, S: Into<String>>(name: S, future: F) -> task::JoinHandle<F::Output>
where
    F: Future + 'static,
    F::Output: 'static,
{
    let name_str = name.into();
    log::trace!("Spawning wasm task: {}", name_str);
    spawn(future)
}

// Verify if the multi thread is supported by the caller
pub fn is_multi_threads_supported() -> bool {
    trace!("is multi thread supported");
    #[cfg(feature = "tokio")]
    {
        let supported = Handle::try_current()
            .map(|v| matches!(v.runtime_flavor(), RuntimeFlavor::MultiThread))
            .unwrap_or(false);
        trace!("multi threads supported: {}", supported);
    
        supported
    }
    #[cfg(not(feature = "tokio"))]
    false
}

// Try blocking on using the current executor available for the thread
// If the current executor is not available, return an error
pub fn try_block_on<F: Future>(future: F) -> Result<F::Output, anyhow::Error> {
    trace!("try block on");
    #[cfg(feature = "tokio")]
    {
        let handle = Handle::try_current()?;
        if matches!(handle.runtime_flavor(), RuntimeFlavor::CurrentThread) {
            trace!("runtime is current thread and may not support blocking, fallback on futures executor");
            Ok(futures::executor::block_on(future))
        } else {
            Ok(handle.block_on(future))
        }
    }
    #[cfg(not(feature = "tokio"))]
    {
        Err(anyhow::anyhow!("Tokio feature is not enabled"))
    }
}

// Block in place if multi thread is supported
// Otherwise, fallback by calling ourself the function
// In a single threaded runtime, we would block the executor
// In a multi threaded runtime, we would block the current thread only
pub fn block_in_place_safe<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    trace!("block in place if multi thread is supported");
    if is_multi_threads_supported() {
        tokio::task::block_in_place(f)
    } else {
        f()
    }
}