pub mod rpc;
pub mod websocket;
pub mod getwork_server;

use crate::core::{error::BlockchainError, blockchain::Blockchain};
use crate::rpc::getwork_server::GetWorkServer;
use crate::rpc::websocket::WebSocketHandler;
use actix::Addr;
use actix_web::web::{Path, Data};
use actix_web::{web::{self, Payload}, error::Error, HttpResponse, Responder, HttpRequest};
use actix_web_actors::ws::WsResponseBuilder;
use serde::Serialize;
use serde_json::json;
use tokio::sync::Mutex;
use xelis_common::api::daemon::{NotifyEvent, EventResult};
use xelis_common::config;
use xelis_common::crypto::address::Address;
use xelis_common::rpc_server::{RpcServer, InternalRpcError, JSON_RPC_VERSION, RpcServerHandler};
use std::borrow::Cow;
use std::{sync::Arc, collections::HashMap};
use log::{trace, info, error, debug};
use self::getwork_server::{GetWorkWebSocketHandler, SharedGetWorkServer};
use self::websocket::Response;

pub type SharedDaemonRpcServer = Arc<DaemonRpcServer>;

pub struct DaemonRpcServer {
    inner: RpcServer<Arc<Blockchain>>,
    clients: Mutex<HashMap<Addr<WebSocketHandler>, HashMap<NotifyEvent, Option<usize>>>>, // all websocket clients connected with subscriptions linked
    getwork: Option<SharedGetWorkServer>,
    blockchain: Arc<Blockchain>
}

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
            clients: Mutex::new(HashMap::new()),
            blockchain,
            getwork,
        });

        info!("RPC Server will run at {}", bind_address);
        if let Err(e) = server.inner.start_with(server.clone(), bind_address, || vec![("/",  web::get().to(index)), ("/ws", web::get().to(ws_endpoint)), ("/getwork/{address}/{worker}", web::get().to(getwork_endpoint))]).await {
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

    pub async fn add_client(&self, addr: Addr<WebSocketHandler>) {
        let mut clients = self.clients.lock().await;
        clients.insert(addr, HashMap::new());
    }

    pub async fn remove_client(&self, addr: &Addr<WebSocketHandler>) {
        let mut clients = self.clients.lock().await;
        let deleted = clients.remove(addr).is_some();
        trace!("WebSocket client {:?} deleted: {}", addr, deleted);
    }

    pub async fn subscribe_client_to(&self, addr: &Addr<WebSocketHandler>, subscribe: NotifyEvent, id: Option<usize>) -> Result<(), ApiError> {
        let mut clients = self.clients.lock().await;
        let subscriptions = clients.get_mut(addr).ok_or_else(|| ApiError::ClientNotRegistered)?;
        subscriptions.insert(subscribe, id);
        Ok(())
    }

    pub async fn unsubscribe_client_from(&self, addr: &Addr<WebSocketHandler>, subscribe: &NotifyEvent) -> Result<(), ApiError> {
        let mut clients = self.clients.lock().await;
        let subscriptions = clients.get_mut(addr).ok_or_else(|| ApiError::ClientNotRegistered)?;
        subscriptions.remove(subscribe);
        Ok(())
    }

    // notify all clients connected to the websocket which have subscribed to the event sent.
    // each client message is sent through a tokio task in case an error happens and to prevent waiting on others clients
    pub async fn notify_clients<V: Serialize>(&self, notify: &NotifyEvent, value: V) -> Result<(), InternalRpcError> {
        let value = json!(EventResult { event: Cow::Borrowed(notify), value: json!(value) });
        let clients = self.clients.lock().await;
        for (addr, subs) in clients.iter() {
            if let Some(id) = subs.get(notify) {
                let addr = addr.clone();
                let response = Response(json!({
                    "jsonrpc": JSON_RPC_VERSION,
                    "id": id,
                    "result": value
                }));
                tokio::spawn(async move {
                    match addr.send(response).await {
                        Ok(response) => {
                            if let Err(e) = response {
                                debug!("Error while sending websocket event: {} ", e);
                            } 
                        }
                        Err(e) => {
                            debug!("Error while sending on mailbox: {}", e);
                        }
                    };
                });
            }
        }
        Ok(())
    }

    pub fn getwork_server(&self) -> &Option<SharedGetWorkServer> {
        &self.getwork
    }
}

impl RpcServerHandler<Arc<Blockchain>> for DaemonRpcServer {
    fn get_rpc_server(&self) -> &RpcServer<Arc<Blockchain>> {
        &self.inner
    }

    fn get_data(&self) -> &Arc<Blockchain> {
        &self.blockchain
    }
}

async fn index() -> impl Responder {
    HttpResponse::Ok().body(format!("Hello, world!\nRunning on: {}", config::VERSION))
}

async fn ws_endpoint(server: Data<SharedDaemonRpcServer>, request: HttpRequest, stream: Payload) -> Result<HttpResponse, Error> {
    let (addr, response) = WsResponseBuilder::new(WebSocketHandler::new(server.get_ref().clone()), &request, stream).start_with_addr()?;
    trace!("New client connected to WebSocket: {:?}", addr);
    server.add_client(addr).await;

    Ok(response)
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