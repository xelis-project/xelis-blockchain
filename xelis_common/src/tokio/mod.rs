mod thread_pool;

use log::trace;

pub use thread_pool::ThreadPool;

#[cfg(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
pub use tokio_with_wasm::*;

#[cfg(not(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
)))]
pub use tokio::*;

use runtime::{Handle, RuntimeFlavor};

// Spawn a new task with a name
// If the tokio_unstable feature is enabled, the task will be named
#[inline(always)]
#[cfg(not(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
)))]
#[track_caller]
pub fn spawn_task<Fut, S: Into<String>>(name: S, future: Fut) -> task::JoinHandle<Fut::Output>
where
    Fut: std::future::Future + Send + 'static,
    Fut::Output: Send + 'static,
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
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
pub fn spawn_task<Fut, S: Into<String>>(name: S, future: Fut) -> task::JoinHandle<Fut::Output>
where
    Fut: std::future::Future + 'static,
    Fut::Output: 'static,
{
    let name_str = name.into();
    log::trace!("Spawning wasm task: {}", name_str);
    spawn(future)
}

// Verify if the multi thread is supported by the caller
pub fn is_multi_threads_supported() -> bool {
    trace!("is multi thread supported");
    let supported = Handle::try_current()
        .map(|v| matches!(v.runtime_flavor(), RuntimeFlavor::MultiThread))
        .unwrap_or(false);
    trace!("multi threads supported: {}", supported);

    supported
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