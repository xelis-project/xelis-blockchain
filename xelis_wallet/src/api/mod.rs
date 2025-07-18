
#[cfg(any(feature = "xswd", feature = "api_server"))]
mod rpc;

#[cfg(feature = "api_server")]
mod server;
#[cfg(feature = "xswd")]
mod xswd;

#[cfg(feature = "api_server")]
pub use server::*;

#[cfg(feature = "xswd")]
pub use self::{
    xswd::*,
    rpc::register_methods as register_rpc_methods
};
