pub mod rpc;
pub mod getwork_server;

use crate::core::{error::BlockchainError, blockchain::Blockchain};
use crate::rpc::getwork_server::GetWorkServer;
use actix_web::dev::ServerHandle;
use actix_web::{
    get, HttpServer, App, HttpResponse, Responder, HttpRequest, web::{
        self, Path, Data, Payload
    },
    error::Error
};
use actix_web_actors::ws::WsResponseBuilder;
use serde_json::Value;
use tokio::sync::Mutex;
use xelis_common::api::daemon::NotifyEvent;
use xelis_common::config;
use xelis_common::crypto::address::Address;
use xelis_common::rpc_server::websocket::{EventWebSocketHandler, WebSocketServerShared, WebSocketServer};
use xelis_common::rpc_server::{InternalRpcError, RPCHandler, RPCServerHandler, json_rpc, websocket, WebSocketServerHandler};
use std::sync::Arc;
use log::{trace, info, error, debug, warn};
use self::getwork_server::{GetWorkWebSocketHandler, SharedGetWorkServer};

pub type SharedDaemonRpcServer = Arc<DaemonRpcServer>;

pub struct DaemonRpcServer {
    handle: Mutex<Option<ServerHandle>>,
    rpc_handler: Arc<RPCHandler<Arc<Blockchain>>>,
    websocket: WebSocketServerShared<EventWebSocketHandler<Arc<Blockchain>, NotifyEvent>>,
    getwork: Option<SharedGetWorkServer>
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("client not registered")]
    ClientNotRegistered,
    #[error("invalid address")]
    ExpectedNormalAddress,
    #[error("P2p engine is not running")]
    NoP2p,
    #[error("WebSocket server is not started")]
    NoWebSocketServer
}

impl DaemonRpcServer {
    pub async fn new(bind_address: String, blockchain: Arc<Blockchain>, disable_getwork_server: bool) -> Result<SharedDaemonRpcServer, BlockchainError> {
        let getwork: Option<SharedGetWorkServer> = if !disable_getwork_server {
            info!("Creating GetWork server...");
            Some(Arc::new(GetWorkServer::new(blockchain.clone())))
        } else {
            None
        };

        // create the RPC Handler which will register and contains all available methods
        let mut rpc_handler = RPCHandler::new(blockchain);
        rpc::register_methods(&mut rpc_handler);

        let rpc_handler = Arc::new(rpc_handler);

        // create the default websocket server (support event & rpc methods)
        let ws = WebSocketServer::new(EventWebSocketHandler::new(rpc_handler.clone()));

        let server = Arc::new(Self {
            handle: Mutex::new(None),
            websocket: ws,
            rpc_handler,
            getwork,
        });

        {
            let clone = Arc::clone(&server);
            let http_server = HttpServer::new(move || {
                let server = Arc::clone(&clone);
                App::new().app_data(web::Data::new(server))
                    .route("/json_rpc", web::post().to(json_rpc::<Arc<Blockchain>, DaemonRpcServer>))
                    .route("/ws", web::get().to(websocket::<EventWebSocketHandler<Arc<Blockchain>, NotifyEvent>, DaemonRpcServer>))
                    .service(index)
                    .service(getwork_endpoint)
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

    pub async fn notify_clients(&self, event: &NotifyEvent, value: Value) -> Result<(), anyhow::Error> {
        self.get_websocket().get_handler().notify(event, value).await;
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

    pub fn getwork_server(&self) -> &Option<SharedGetWorkServer> {
        &self.getwork
    }
}

impl WebSocketServerHandler<EventWebSocketHandler<Arc<Blockchain>, NotifyEvent>> for DaemonRpcServer {
    fn get_websocket(&self) -> &WebSocketServerShared<EventWebSocketHandler<Arc<Blockchain>, NotifyEvent>> {
        &self.websocket
    }
}

impl RPCServerHandler<Arc<Blockchain>> for DaemonRpcServer {
    fn get_rpc_handler(&self) -> &RPCHandler<Arc<Blockchain>> {
        &self.rpc_handler
    }
}


#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body(format!("Hello, world!\nRunning on: {}", config::VERSION))
}

#[get("/getwork/{address}/{worker}")]
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

            if address.is_mainnet() != server.get_rpc_handler().get_data().get_network().is_mainnet() {
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