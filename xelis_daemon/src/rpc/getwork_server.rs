use std::{sync::Arc, collections::HashMap};
use actix::{Actor, AsyncContext, Handler, Message as TMessage, StreamHandler, Addr};
use actix_web::web::Data;
use actix_web_actors::ws::{ProtocolError, Message, WebsocketContext};
use log::{debug, warn};
use tokio::sync::Mutex;
use xelis_common::{crypto::key::PublicKey, globals::get_current_timestamp};
use crate::rpc::{RpcResponseError, RpcError};

use super::SharedRpcServer;

pub type SharedGetWorkServer = Data<Arc<GetWorkServer>>;
pub struct Response; // TODO Notify, BlockAccepted, BlockRejected
impl TMessage for Response {
    type Result = Result<(), RpcError>;
}

pub struct Miner {
    key: PublicKey, // public key of account (address)
    name: String, // worker name
    blocks_found: usize, // blocks found since he is connected
}

impl Miner {
    pub fn new(key: PublicKey, name: String) -> Self {
        Self {
            key,
            name,
            blocks_found: 0
        }
    }

    pub fn get_public_key(&self) -> &PublicKey {
        &self.key
    }

    pub fn get_name(&self) -> &String {
        &self.name
    }

    pub fn get_blocks_found(&self) -> usize {
        self.blocks_found
    }
}

pub struct GetWorkWebSocketHandler {
    server: SharedGetWorkServer
}

impl GetWorkWebSocketHandler {
    pub fn new(server: SharedGetWorkServer) -> Self {
        Self {
            server
        }
    }
}

impl Actor for GetWorkWebSocketHandler {
    type Context = WebsocketContext<Self>;
}

impl StreamHandler<Result<Message, ProtocolError>> for GetWorkWebSocketHandler {
    fn handle(&mut self, msg: Result<Message, ProtocolError>, ctx: &mut Self::Context) {
        match msg {
            Ok(Message::Text(text)) => {
                let address = ctx.address();
                // TODO read submitted block
            },
            Ok(Message::Close(reason)) => {
                ctx.close(reason);
            },
            msg => {
                debug!("Abnormal message received: {:?}. Closing connection", msg);
                let error = RpcResponseError::new(None, RpcError::InvalidRequest);
                ctx.text(error.to_json().to_string());
                ctx.close(None);
            }
        }
    }

    fn finished(&mut self, ctx: &mut Self::Context) {
        let server = self.server.clone();
        let address = ctx.address();
        let fut = async move {
            server.delete_miner(&address).await;
        };
        ctx.wait(actix::fut::wrap_future(fut));
    }
}

impl Handler<Response> for GetWorkWebSocketHandler {
    type Result = Result<(), RpcError>;

    fn handle(&mut self, msg: Response, ctx: &mut Self::Context) -> Self::Result {
        todo!("send response to client")
    }
}

pub struct GetWorkServer {
    miners: Mutex<HashMap<Addr<GetWorkWebSocketHandler>, Miner>>,
    server: SharedRpcServer
}

impl GetWorkServer {
    pub fn new(server: SharedRpcServer) -> Self {
        Self {
            miners: Mutex::new(HashMap::new()),
            server
        }
    }

    pub async fn add_miner(&self, addr: Addr<GetWorkWebSocketHandler>, key: PublicKey, worker: String) {
        let mut miners = self.miners.lock().await;
        miners.insert(addr, Miner::new(key, worker));
    }

    pub async fn delete_miner(&self, addr: &Addr<GetWorkWebSocketHandler>) {
        let mut miners = self.miners.lock().await;
        miners.remove(addr);
    }

    // notify every miners connected to the getwork server
    // each miner have his own task so nobody wait on other
    pub async fn notify_new_job(&self) -> Result<(), RpcError> {
        let blockchain = self.server.get_blockchain();
        // TODO build a generic block template and replace public key by the one of each miner + random nonce

        let mut miners = self.miners.lock().await;
        for (addr, miner) in miners.iter_mut() {
            let addr = addr.clone();
            tokio::spawn(async move {
                match addr.send(Response).await { // TODO send block template
                   Ok(request) => {
                    if let Err(e) = request {
                        warn!("Error while sending new job to addr {:?}: {}", addr, e);
                    }
                   },
                   Err(e) => {
                    warn!("Error while notifying new job to addr {:?}: {}", addr, e);
                   }
                }
            });
        }
        Ok(())
    }
}