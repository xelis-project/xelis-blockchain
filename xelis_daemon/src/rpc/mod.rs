pub mod rpc;
pub mod getwork_server;

use crate::{
    core::{
        storage::Storage,
        error::BlockchainError,
        blockchain::Blockchain
    },
    rpc::getwork_server::GetWorkServer,
};
use actix_web::{
    get,
    HttpServer,
    App,
    HttpResponse,
    Responder,
    HttpRequest,
    web::{
        self,
        Path,
        Data,
        Payload
    },
    dev::ServerHandle,
    error::Error
};
use actix_web_actors::ws::WsResponseBuilder;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use xelis_common::{
    api::daemon::NotifyEvent,
    config,
    crypto::Address,
    rpc_server::{
        websocket::{
            EventWebSocketHandler,
            WebSocketServerShared,
            WebSocketServer
        },
        InternalRpcError,
        RPCHandler,
        RPCServerHandler,
        json_rpc,
        websocket,
        WebSocketServerHandler,
    },
};
use std::{
    collections::HashSet,
    sync::Arc,
};
use log::{
    trace,
    debug,
    info,
    warn,
    error,
};
use self::getwork_server::{
    GetWorkWebSocketHandler,
    SharedGetWorkServer
};

pub type SharedDaemonRpcServer<S> = Arc<DaemonRpcServer<S>>;

pub struct DaemonRpcServer<S: Storage> {
    handle: Mutex<Option<ServerHandle>>,
    websocket: WebSocketServerShared<EventWebSocketHandler<Arc<Blockchain<S>>, NotifyEvent>>,
    getwork: Option<SharedGetWorkServer<S>>
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

impl<S: Storage> DaemonRpcServer<S> {
    pub async fn new(bind_address: String, blockchain: Arc<Blockchain<S>>, disable_getwork_server: bool) -> Result<SharedDaemonRpcServer<S>, BlockchainError> {
        let getwork: Option<SharedGetWorkServer<S>> = if !disable_getwork_server {
            info!("Creating GetWork server...");
            Some(Arc::new(GetWorkServer::new(blockchain.clone())))
        } else {
            None
        };

        // create the RPC Handler which will register and contains all available methods
        let mut rpc_handler = RPCHandler::new(blockchain);
        rpc::register_methods(&mut rpc_handler);

        // create the default websocket server (support event & rpc methods)
        let ws = WebSocketServer::new(EventWebSocketHandler::new(rpc_handler));

        let server = Arc::new(Self {
            handle: Mutex::new(None),
            websocket: ws,
            getwork,
        });

        {
            let clone = Arc::clone(&server);
            let http_server = HttpServer::new(move || {
                let server = Arc::clone(&clone);
                App::new().app_data(web::Data::from(server))
                    // Traditional HTTP
                    .route("/json_rpc", web::post().to(json_rpc::<Arc<Blockchain<S>>, DaemonRpcServer<S>>))
                    // WebSocket support
                    .route("/json_rpc", web::get().to(websocket::<EventWebSocketHandler<Arc<Blockchain<S>>, NotifyEvent>, DaemonRpcServer<S>>))
                    .route("/getwork/{address}/{worker}", web::get().to(getwork_endpoint::<S>))
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

    pub async fn get_tracked_events(&self) -> HashSet<NotifyEvent> {
        self.get_websocket().get_handler().get_tracked_events().await
    }

    pub async fn is_event_tracked(&self, event: &NotifyEvent) -> bool {
        self.get_websocket().get_handler().is_event_tracked(event).await
    }

    pub async fn notify_clients_with<V: serde::Serialize>(&self, event: &NotifyEvent, value: V) {
        if let Err(e) = self.notify_clients(event, json!(value)).await {
            error!("Error while notifying event {:?}: {}", event, e);
        }
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

    pub fn getwork_server(&self) -> &Option<SharedGetWorkServer<S>> {
        &self.getwork
    }
}

impl<S: Storage> WebSocketServerHandler<EventWebSocketHandler<Arc<Blockchain<S>>, NotifyEvent>> for DaemonRpcServer<S> {
    fn get_websocket(&self) -> &WebSocketServerShared<EventWebSocketHandler<Arc<Blockchain<S>>, NotifyEvent>> {
        &self.websocket
    }
}

impl<S: Storage> RPCServerHandler<Arc<Blockchain<S>>> for DaemonRpcServer<S> {
    fn get_rpc_handler(&self) -> &RPCHandler<Arc<Blockchain<S>>> {
        self.get_websocket().get_handler().get_rpc_handler()
    }
}


#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body(format!("Hello, world!\nRunning on: {}", config::VERSION))
}

async fn getwork_endpoint<S: Storage>(server: Data<DaemonRpcServer<S>>, request: HttpRequest, stream: Payload, path: Path<(String, String)>) -> Result<HttpResponse, Error> {
    match &server.getwork {
        Some(getwork) => {
            let (addr, worker) = path.into_inner();
            if worker.len() > 32 {
                return Ok(HttpResponse::BadRequest().body("Worker name must be less or equal to 32 chars"))
            }

            let address: Address = match Address::from_string(&addr) {
                Ok(address) => address,
                Err(e) => {
                    debug!("Invalid miner address for getwork server: {}", e);
                    return Ok(HttpResponse::BadRequest().body("Invalid miner address for getwork server"))
                }
            };
            if !address.is_normal() {
                return Ok(HttpResponse::BadRequest().body("Address should be in normal format"))
            }

            let network = server.get_rpc_handler().get_data().get_network();
            if address.is_mainnet() != network.is_mainnet() {
                return Ok(HttpResponse::BadRequest().body(format!("Address is not in same network state, should be in {} mode", network.to_string().to_lowercase())))
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