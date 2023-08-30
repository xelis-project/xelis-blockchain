use std::sync::Arc;

use actix_web_httpauth::{middleware::HttpAuthentication, extractors::basic::BasicAuth};
use anyhow::Result;
use log::{info, warn};
use tokio::sync::Mutex;
use xelis_common::{config, rpc_server::{RPCHandler, RPCServerHandler, json_rpc}};
use actix_web::{get, HttpResponse, Responder, HttpServer, web::{Data, self}, App, dev::{ServerHandle, ServiceRequest}, Error, error::{ErrorUnauthorized, ErrorBadGateway, ErrorBadRequest}};
use crate::wallet::Wallet;

use super::rpc;

pub type WalletRpcServerShared = Arc<WalletRpcServer>;

pub struct AuthConfig {
    pub username: String,
    pub password: String
}

pub struct WalletRpcServer {
    handle: Mutex<Option<ServerHandle>>,
    rpc_handler: Arc<RPCHandler<Arc<Wallet>>>,
    auth_config: Option<AuthConfig>
}

impl WalletRpcServer {
    pub async fn new(bind_address: String, wallet: Arc<Wallet>, auth_config: Option<AuthConfig>) -> Result<WalletRpcServerShared> {
        let mut rpc_handler = RPCHandler::new(wallet);
        rpc::register_methods(&mut rpc_handler);

        let rpc_handler = Arc::new(rpc_handler);
        let server = Arc::new(Self {
            handle: Mutex::new(None),
            rpc_handler,
            auth_config
        });

        {
            let clone = Arc::clone(&server);
            let http_server = HttpServer::new(move || {
                let server = Arc::clone(&clone);
                let auth = HttpAuthentication::basic(auth);
                App::new()
                    .app_data(Data::from(server))
                    .wrap(auth)
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

    async fn authenticate(&self, credentials: BasicAuth) -> Result<(), Error> {
        if let Some(config) = &self.auth_config {
            let user = credentials.user_id();
            let password = credentials.password().ok_or(ErrorBadRequest("Missing password"))?;

            if *config.username != *user || *config.password != *password {
                return Err(ErrorUnauthorized("Username/password are invalid"))
            }
        }

        Ok(())
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

async fn auth(request: ServiceRequest, credentials: BasicAuth) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let data: Option<&Data<WalletRpcServer>> = request.app_data();
    match data {
        Some(server) => match server.authenticate(credentials).await {
            Ok(_) => Ok(request),
            Err(e) => Err((e, request))
        },
        None => Err((ErrorBadGateway("RPC Server was not found"), request))
    }
}

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body(format!("Hello, world!\nRunning on: {}", config::VERSION))
}