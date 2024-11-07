use std::sync::Arc;

use actix_web_httpauth::{
    middleware::HttpAuthentication,
    extractors::basic::BasicAuth
};
use anyhow::Result;
use log::{info, warn};
use xelis_common::{
    tokio::{
        spawn_task,
        sync::Mutex
    },
    api::wallet::NotifyEvent,
    config,
    rpc_server::{
        json_rpc,
        websocket,
        websocket::{
            EventWebSocketHandler,
            WebSocketServer,
            WebSocketServerShared
        },
        RPCHandler,
        RPCServerHandler,
        WebSocketServerHandler
    }
};
use actix_web::{
    get,
    HttpResponse,
    Responder,
    HttpServer,
    web::{Data, self},
    App,
    dev::{ServerHandle, ServiceRequest},
    Error,
    error::{ErrorUnauthorized, ErrorBadGateway, ErrorBadRequest}
};

pub type WalletRpcServerShared<W> = Arc<WalletRpcServer<W>>;

pub struct AuthConfig {
    pub username: String,
    pub password: String
}

pub struct WalletRpcServer<W>
where
    W: Clone + Send + Sync + 'static
{
    handle: Mutex<Option<ServerHandle>>,
    websocket: WebSocketServerShared<EventWebSocketHandler<W, NotifyEvent>>,
    auth_config: Option<AuthConfig>
}

impl<W> WalletRpcServer<W>
where
    W: Clone + Send + Sync + 'static
{
    pub async fn new(bind_address: String, rpc_handler: RPCHandler<W>, auth_config: Option<AuthConfig>, threads: Option<usize>) -> Result<WalletRpcServerShared<W>> {
        let server = Arc::new(Self {
            handle: Mutex::new(None),
            websocket: WebSocketServer::new(EventWebSocketHandler::new(rpc_handler)),
            auth_config
        });

        {
            let clone = Arc::clone(&server);
            let mut builder = HttpServer::new(move || {
                let server = Arc::clone(&clone);
                let auth = HttpAuthentication::basic(auth::<W>);
                App::new()
                    .app_data(Data::from(server))
                    .wrap(auth)
                    // WebSocket support
                    .route("/json_rpc", web::get().to(websocket::<EventWebSocketHandler<W, NotifyEvent>, Self>))
                    // HTTP support
                    .route("/json_rpc", web::post().to(json_rpc::<W, WalletRpcServer<W>>))
                    .service(index)
            })
            .disable_signals()
            .bind(&bind_address)?;

            if let Some(threads) = threads {
                info!("Setting the number of workers to: {}", threads);
                builder = builder.workers(threads);
            }

            let http_server = builder.run();
            { // save the server handle to be able to stop it later
                let handle = http_server.handle();
                let mut lock = server.handle.lock().await;
                *lock = Some(handle);

            }
            spawn_task("rpc-server", http_server);
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

impl<W> WebSocketServerHandler<EventWebSocketHandler<W, NotifyEvent>> for WalletRpcServer<W>
where
    W: Clone + Send + Sync + 'static
{
    fn get_websocket(&self) -> &WebSocketServerShared<EventWebSocketHandler<W, NotifyEvent>> {
        &self.websocket
    }
}

impl<W> RPCServerHandler<W> for WalletRpcServer<W>
where
    W: Clone + Send + Sync + 'static
{
    fn get_rpc_handler(&self) -> &RPCHandler<W> {
        &self.get_websocket().get_handler().get_rpc_handler()
    }
}

async fn auth<W>(request: ServiceRequest, credentials: BasicAuth) -> Result<ServiceRequest, (Error, ServiceRequest)>
where
    W: Clone + Send + Sync + 'static
{
    let data: Option<&Data<WalletRpcServer<W>>> = request.app_data();
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