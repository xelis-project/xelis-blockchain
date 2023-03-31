/*use std::sync::Arc;

use anyhow::Result;
use xelis_common::rpc_server::{RpcServer, RpcServerHandler};
use actix_web::{HttpResponse, Responder, web};
use crate::wallet::Wallet;
use log::error;

pub struct WalletRpcServer {
    inner:  RpcServer<Arc<Wallet>, (), WalletRpcServer>,
    wallet: Arc<Wallet>
}

impl WalletRpcServer {
    pub async fn new(wallet: Arc<Wallet>) -> Result<Arc<Self>> {
        let inner = RpcServer::new();
        let server = Arc::new(Self {
            inner,
            wallet
        });

        if let Err(e) = server.inner.start_with(server.clone(), "127.0.0.1:2020", || vec![("/", web::get().to(index))]).await {
            error!("Failed to start RPC Server: {}", e);
        }

        Ok(server)
    }
}

impl RpcServerHandler<Arc<Wallet>, ()> for WalletRpcServer {
    fn get_rpc_server(&self) -> &RpcServer<Arc<Wallet>, (), WalletRpcServer> {
        &self.inner
    }

    fn get_data(&self) -> &Arc<Wallet> {
        &self.wallet
    }
}

async fn index() -> impl Responder {
    HttpResponse::Ok().body(format!("Hello, world!\nRunning on"))
}*/