mod rpc;
mod rpc_server;
mod xswd;

pub use self::{
    rpc_server::{WalletRpcServer, WalletRpcServerShared, AuthConfig},
    xswd::XSWD
};

pub enum APIServer {
    RPCServer(WalletRpcServerShared),
    XSWD(XSWD)
}

impl APIServer {
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