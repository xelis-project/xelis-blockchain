pub mod rpc;
pub mod getwork;

use crate::core::{
    blockchain::Blockchain,
    config::RPCConfig,
    error::BlockchainError,
    storage::Storage
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
        Data,
        Payload
    },
    dev::ServerHandle,
    error::Error
};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use xelis_common::{
    api::daemon::NotifyEvent,
    config,
    rpc_server::{
        json_rpc,
        websocket,
        websocket::{
            EventWebSocketHandler,
            WebSocketServer,
            WebSocketServerShared
        },
        InternalRpcError,
        RPCHandler,
        RPCServerHandler,
        WebSocketServerHandler
    },
    tokio::spawn_task
};
use std::{
    collections::HashSet,
    sync::Arc,
};
use log::{
    info,
    warn,
    error,
};
use getwork::GetWorkServer;

pub type SharedDaemonRpcServer<S> = Arc<DaemonRpcServer<S>>;

pub struct DaemonRpcServer<S: Storage> {
    handle: Mutex<Option<ServerHandle>>,
    websocket: WebSocketServerShared<EventWebSocketHandler<Arc<Blockchain<S>>, NotifyEvent>>,
    getwork: Option<WebSocketServerShared<GetWorkServer<S>>>
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
    pub async fn new(
        blockchain: Arc<Blockchain<S>>,
        config: RPCConfig
    ) -> Result<SharedDaemonRpcServer<S>, BlockchainError> {
        let getwork = if !config.getwork.disable_getwork_server {
            info!("Creating GetWork server...");
            Some(WebSocketServer::new(GetWorkServer::new(
                blockchain.clone(),
                config.getwork.getwork_rate_limit_ms,
                config.getwork.getwork_notify_job_concurrency
            )))
        } else {
            None
        };

        // create the RPC Handler which will register and contains all available methods
        let mut rpc_handler = RPCHandler::new(blockchain);
        rpc::register_methods(&mut rpc_handler, !config.getwork.disable_getwork_server);

        // create the default websocket server (support event & rpc methods)
        let ws = WebSocketServer::new(EventWebSocketHandler::new(rpc_handler, config.rpc_notify_events_concurrency));

        let server = Arc::new(Self {
            handle: Mutex::new(None),
            websocket: ws,
            getwork,
        });

        {
            let clone = Arc::clone(&server);
            let builder = HttpServer::new(move || {
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
            .bind(&config.rpc_bind_address)?;

            let http_server = builder.workers(config.rpc_threads).run();

            { // save the server handle to be able to stop it later
                let handle = http_server.handle();
                let mut lock = server.handle.lock().await;
                *lock = Some(handle);

            }
            spawn_task("rpc-server", http_server);
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

    pub fn getwork_server(&self) -> &Option<WebSocketServerShared<GetWorkServer<S>>> {
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

async fn getwork_endpoint<S: Storage>(server: Data<DaemonRpcServer<S>>, request: HttpRequest, stream: Payload) -> Result<HttpResponse, Error> {
    match &server.getwork {
        Some(getwork) => getwork.handle_connection(request, stream).await,
        None => Ok(HttpResponse::NotFound().reason("GetWork server is not enabled").finish()) // getwork server is not started
    }
}