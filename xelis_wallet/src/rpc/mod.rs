mod rpc;

use std::sync::Arc;

use anyhow::Result;
use log::{info, warn};
use tokio::sync::Mutex;
use xelis_common::{config, rpc_server::{RPCHandler, RPCServerHandler, json_rpc}};
use actix_web::{get, HttpResponse, Responder, HttpServer, web::{Data, self}, App, dev::ServerHandle};
use crate::wallet::Wallet;

pub struct WalletRpcServer {
    handle: Mutex<Option<ServerHandle>>,
    rpc_handler: Arc<RPCHandler<Arc<Wallet>>>,
}

impl WalletRpcServer {
    pub async fn new(bind_address: String, wallet: Arc<Wallet>) -> Result<Arc<Self>> {
        let mut rpc_handler = RPCHandler::new(wallet);
        rpc::register_methods(&mut rpc_handler);

        let rpc_handler = Arc::new(rpc_handler);
        let server = Arc::new(Self {
            handle: Mutex::new(None),
            rpc_handler
        });

        {
            let clone = Arc::clone(&server);
            let http_server = HttpServer::new(move || {
                let server = Arc::clone(&clone);
                App::new().app_data(Data::from(server))
                    .route("/json_rpc", web::post().to(json_rpc::<Arc<Wallet>, WalletRpcServer>))
                    .service(index)
            })
            .disable_signals()
            .bind(&bind_address)?
            .run();

            { // save the server handle to be able to stop it later
                let handle = http_server.handle();
                let mut lock = server.handle.lock().await;
                *lock = Some(handle);

            }
            tokio::spawn(http_server);
        }

        Ok(server)
    }

    pub async fn stop(&self) {
        info!("Stopping RPC Server...");
        let mut handle = self.handle.lock().await;
        if let Some(handle) = handle.take() {
            handle.stop(false).await;
            info!("RPC Server is now stopped!");
        } else {
            warn!("RPC Server is not running!");
        }
    }
}

impl RPCServerHandler<Arc<Wallet>> for WalletRpcServer {
    fn get_rpc_handler(&self) -> &RPCHandler<Arc<Wallet>> {
        &self.rpc_handler
    }
}

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body(format!("Hello, world!\nRunning on: {}", config::VERSION))
}