pub mod rpc;
pub mod getwork_server;

use crate::core::{error::BlockchainError, blockchain::Blockchain};
use crate::rpc::getwork_server::GetWorkServer;
use actix_web::web::{Path, Data};
use actix_web::{web::{self, Payload}, error::Error, HttpResponse, Responder, HttpRequest};
use actix_web_actors::ws::WsResponseBuilder;
use xelis_common::api::daemon::NotifyEvent;
use xelis_common::config;
use xelis_common::crypto::address::Address;
use xelis_common::rpc_server::{RpcServer, InternalRpcError, RpcServerHandler};
use std::ops::Deref;
use std::sync::Arc;
use log::{trace, info, error, debug};
use self::getwork_server::{GetWorkWebSocketHandler, SharedGetWorkServer};

pub type SharedDaemonRpcServer = Arc<DaemonRpcServer>;

pub struct DaemonRpcServer {
    inner: RpcServer<Arc<Blockchain>, NotifyEvent, Self>,
    getwork: Option<SharedGetWorkServer>,
    blockchain: Arc<Blockchain>
}

unsafe impl Sync for DaemonRpcServer {}
unsafe impl Send for DaemonRpcServer {}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("client not registered")]
    ClientNotRegistered,
    #[error("invalid address")]
    ExpectedNormalAddress,
    #[error("P2p engine is not running")]
    NoP2p
}

impl DaemonRpcServer {
    pub async fn new(bind_address: String, blockchain: Arc<Blockchain>, disable_getwork_server: bool) -> Result<SharedDaemonRpcServer, BlockchainError> {
        let getwork: Option<SharedGetWorkServer> = if !disable_getwork_server {
            info!("Creating GetWork server...");
            Some(Arc::new(GetWorkServer::new(blockchain.clone())))
        } else {
            None
        };

        let mut inner = RpcServer::new();
        rpc::register_methods(&mut inner);

        let server = Arc::new(Self {
            inner,
            blockchain,
            getwork,
        });

        info!("RPC Server will run at {}", bind_address);
        if let Err(e) = server.inner.start_with(server.clone(), bind_address, || vec![("/",  web::get().to(index)), ("/getwork/{address}/{worker}", web::get().to(getwork_endpoint))]).await {
            error!("Failed to start RPC Server: {}", e);
        }

        Ok(server)
    }

    pub async fn stop(&self) {
        info!("Stopping RPC Server...");
        self.inner.stop(true).await;
        info!("RPC Server is now stopped!");
    }

    pub fn get_blockchain(&self) -> &Arc<Blockchain> {
        &self.blockchain
    }

    pub fn getwork_server(&self) -> &Option<SharedGetWorkServer> {
        &self.getwork
    }
}

impl RpcServerHandler<Arc<Blockchain>, NotifyEvent> for DaemonRpcServer {
    fn get_rpc_server(&self) -> &RpcServer<Arc<Blockchain>, NotifyEvent, Self> {
        &self.inner
    }

    fn get_data(&self) -> &Arc<Blockchain> {
        &self.blockchain
    }
}

impl Deref for DaemonRpcServer {
    type Target = RpcServer<Arc<Blockchain>, NotifyEvent, Self>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

async fn index() -> impl Responder {
    HttpResponse::Ok().body(format!("Hello, world!\nRunning on: {}", config::VERSION))
}

async fn getwork_endpoint(server: Data<SharedDaemonRpcServer>, request: HttpRequest, stream: Payload, path: Path<(String, String)>) -> Result<HttpResponse, Error> {
    match &server.getwork {
        Some(getwork) => {
            let (addr, worker) = path.into_inner();
            if worker.len() > 32 {
                return Ok(HttpResponse::BadRequest().reason("Worker name must be less or equal to 32 chars").finish())
            }

            let address: Address<'_> = match Address::from_string(&addr) {
                Ok(address) => address,
                Err(e) => {
                    debug!("Invalid miner address for getwork server: {}", e);
                    return Ok(HttpResponse::BadRequest().reason("Invalid miner address for getwork server").finish())
                }
            };
            if !address.is_normal() {
                return Ok(HttpResponse::BadRequest().reason("Address should be in normal format").finish())
            }

            if address.is_mainnet() != server.get_blockchain().get_network().is_mainnet() {
                return Ok(HttpResponse::BadRequest().reason("Address is not in same network state").finish())
            }

            let key = address.to_public_key();
            let (addr, response) = WsResponseBuilder::new(GetWorkWebSocketHandler::new(getwork.clone()), &request, stream).start_with_addr()?;
            trace!("New miner connected to GetWork WebSocket: {:?}", addr);
            getwork.add_miner(addr, key, worker).await;
            Ok(response)
        },
        None => Ok(HttpResponse::NotFound().reason("GetWork server is not enabled").finish()) // getwork server is not started
    }
}