#[cfg(feature = "tokio")]
mod scheduler;

#[cfg(feature = "tokio")]
pub use scheduler::Scheduler;

#[cfg(feature = "tokio")]
mod executor;

#[cfg(feature = "tokio")]
pub use executor::Executor;

#[cfg(feature = "tokio")]
mod thread_pool;

#[cfg(feature = "tokio")]
pub mod sync;

use std::future::Future;
use cfg_if::cfg_if;
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

#[cfg(all(
    feature = "tokio",
    not(all(
        target_arch = "wasm32",
        target_vendor = "unknown",
        target_os = "unknown"
    ))
))]
use std::cell::Cell;

#[cfg(all(
    feature = "tokio",
    not(all(
        target_arch = "wasm32",
        target_vendor = "unknown",
        target_os = "unknown"
    ))
))]
thread_local! {
    static IN_BLOCK_IN_PLACE: Cell<bool> = Cell::new(false);
}

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
    cfg_if! {
        if #[cfg(all(
            feature = "tokio",
            not(all(
                target_arch = "wasm32",
                target_vendor = "unknown",
                target_os = "unknown"
            ))
        ))] {
            let supported = runtime::Handle::try_current()
                .map(|v| matches!(v.runtime_flavor(), runtime::RuntimeFlavor::MultiThread))
                .unwrap_or(false);
            trace!("multi threads supported: {}", supported);
        
            supported
        } else {
            false
        }
    }
}

// Try blocking on using the current executor available for the thread
// If the current executor is not available, return an error
pub fn try_block_on<F: Future>(_future: F) -> Result<F::Output, anyhow::Error> {
    trace!("try block on");
    cfg_if! {
        if #[cfg(feature = "tokio")] {
            if is_multi_threads_supported() {
                cfg_if! {
                    if #[cfg(not(all(
                        target_arch = "wasm32",
                        target_vendor = "unknown",
                        target_os = "unknown"
                    )))] {
                        let handle = runtime::Handle::try_current()?;
                        return if is_in_block_in_place() {
                            trace!("tokio block on directly");
                            Ok(handle.block_on(_future))
                        } else {
                            Ok(block_in_place_internal(|| {
                                trace!("tokio block in place");
                                handle.block_on(_future)
                            }))
                        }
                    }
                }
            }

            // use the futures executor directly
            // This is required because if we are in a Actix
            // context, we can't block on using its executor
            Ok(futures::executor::block_on(_future))
        } else {
            Err(anyhow::anyhow!("Tokio feature is not enabled"))
        }
    }
}

/// Spawn a blocking task that can be awaited
/// This function is safe to use in both single-threaded and multi-threaded contexts.
/// It will use the Tokio runtime if available, or fallback to a direct thread spawn and block
pub fn spawn_blocking_safe<F, R>(f: F) -> impl Future<Output = Result<R, anyhow::Error>>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    cfg_if! {
        if #[cfg(feature = "tokio")] {
            use futures::TryFutureExt;

            trace!("tokio spawn blocking");

            // If tokio is enabled, we spawn a blocking task
            return task::spawn_blocking(f)
                .map_err(|e| anyhow::anyhow!("Failed to spawn blocking task: {}", e))
        } else {
            trace!("simulated spawn blocking");
            return async move {
                // We can use the block_in_place_safe function to ensure we are blocking correctly
                let res = block_in_place_safe(f);
                Ok(res)
            }
        }
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
    #[cfg(all(
        feature = "tokio",
        not(all(
            target_arch = "wasm32",
            target_vendor = "unknown",
            target_os = "unknown"
        ))
    ))]
    if is_multi_threads_supported() {
        return block_in_place_internal(f)
    }

    trace!("direct call block in place");
    f()
}

#[cfg(all(
    feature = "tokio",
    not(all(
        target_arch = "wasm32",
        target_vendor = "unknown",
        target_os = "unknown"
    ))
))]
fn block_in_place_internal<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    trace!("tokio block in place internal");
    let old = is_in_block_in_place();
    set_in_block_in_place(true);
    let res;
    cfg_if! {
        if #[cfg(feature = "tokio-multi-thread")] {
            res = tokio::task::block_in_place(f);
        } else {
            res = f();
        }
    };
    set_in_block_in_place(old);

    res
}

/// Check if we are in a block in place closure
#[inline(always)]
#[cfg(all(
    feature = "tokio",
    not(all(
        target_arch = "wasm32",
        target_vendor = "unknown",
        target_os = "unknown"
    ))
))]
pub fn is_in_block_in_place() -> bool {
    IN_BLOCK_IN_PLACE.with(|flag| flag.get())
}

#[inline(always)]
#[cfg(all(
    feature = "tokio",
    not(all(
        target_arch = "wasm32",
        target_vendor = "unknown",
        target_os = "unknown"
    ))
))]
fn set_in_block_in_place(value: bool) {
    IN_BLOCK_IN_PLACE.with(|flag| flag.set(value));
}