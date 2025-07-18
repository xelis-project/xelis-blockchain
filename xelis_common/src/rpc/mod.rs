#[cfg(feature = "rpc-server")]
pub mod server;

#[cfg(feature = "rpc-client")]
pub mod client;

mod types;
mod rpc_handler;
mod error;

pub use types::*;
pub use error::*;
pub use rpc_handler::*;