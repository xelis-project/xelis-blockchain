use crate::{core::{error::BlockchainError, blockchain::Blockchain}, config};
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder, dev::ServerHandle};
use std::sync::Arc;
use log::info;

#[get("/")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body(format!("Hello, world!\nRunning on: {}", config::VERSION))
}

pub struct RpcServer {
    handle: ServerHandle // keep the server handle to stop it gracefully
}

impl RpcServer {
    pub fn new(bind_address: String, blockchain: Arc<Blockchain>) -> Result<Self, BlockchainError> {
        let server = HttpServer::new(move || {
            let arc = Arc::clone(&blockchain);
            App::new()
                .app_data(web::Data::new(arc))
                .service(hello)
        })
        .disable_signals()
        .bind(&bind_address)?
        .run();
        let handle = server.handle();

        info!("Starting RPC server on: http://{}", bind_address);
        // start the http server
        tokio::spawn(server);
        Ok(Self {
            handle
        })
    }

    pub async fn stop(self) {
        info!("Stopping RPC Server...");
        self.handle.stop(true).await;
    }
}