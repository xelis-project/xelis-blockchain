mod rpc;
mod rpc_server;
mod xswd;

use serde::ser::Serialize;
use xelis_common::{api::wallet::NotifyEvent, rpc_server::WebSocketServerHandler};

pub use self::{
    rpc_server::{WalletRpcServer, WalletRpcServerShared, AuthConfig},
    xswd::{
        XSWD,
        AppStateShared,
        PermissionResult,
        PermissionRequest,
        XSWDPermissionHandler,
        XSWDNodeMethodHandler
    },
    rpc::register_methods as register_rpc_methods
};

pub enum APIServer<W>
where
    W: Clone + Send + Sync + XSWDPermissionHandler + XSWDNodeMethodHandler + 'static
{
    RPCServer(WalletRpcServerShared<W>),
    XSWD(XSWD<W>)
}

impl<W> APIServer<W>
where
    W: Clone + Send + Sync + XSWDPermissionHandler + XSWDNodeMethodHandler + 'static
{
    pub async fn notify_event<V: Serialize>(&self, event: &NotifyEvent, value: &V) {
        let json = serde_json::to_value(value).unwrap();
        match self {
            APIServer::RPCServer(server) => {
                server.get_websocket().get_handler().notify(event, json).await;
            },
            APIServer::XSWD(xswd) => {
                xswd.get_handler().notify(event, json).await;
            }
        }
    }

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