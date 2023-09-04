mod rpc;
mod rpc_server;
mod xswd;

pub use self::{
    rpc_server::{WalletRpcServer, WalletRpcServerShared, AuthConfig},
    xswd::{
        XSWD,
        ApplicationData,
        PermissionResult,
        PermissionRequest,
        XSWDPermissionHandler
    },
    rpc::register_methods as register_rpc_methods
};

pub enum APIServer<W>
where
    W: Clone + Send + Sync + XSWDPermissionHandler + 'static
{
    RPCServer(WalletRpcServerShared),
    XSWD(XSWD<W>)
}

impl<W> APIServer<W>
where
    W: Clone + Send + Sync + XSWDPermissionHandler + 'static
{
    pub async fn stop(self) {
        match self {
            APIServer::RPCServer(server) => {
                server.stop().await;
            },
            APIServer::XSWD(xswd) => {
                xswd.stop().await;
            }
        }
    }
}