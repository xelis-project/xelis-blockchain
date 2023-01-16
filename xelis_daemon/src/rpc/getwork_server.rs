use std::{sync::Arc, collections::HashMap};
use actix::{Actor, AsyncContext, Handler, Message as TMessage, StreamHandler, Addr};
use actix_web_actors::ws::{ProtocolError, Message, WebsocketContext};
use log::{debug, warn};
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use serde_json::json;
use tokio::sync::Mutex;
use xelis_common::{crypto::key::PublicKey, globals::get_current_timestamp, api::daemon::GetBlockTemplateResult, serializer::Serializer, block::EXTRA_NONCE_SIZE};
use crate::{rpc::{RpcResponseError, RpcError}, core::blockchain::Blockchain};

pub type SharedGetWorkServer = Arc<GetWorkServer>;

#[derive(Serialize)]
pub enum Response {
    NewJob(GetBlockTemplateResult),
    BlockAccepted,
    BlockRejected
}

impl TMessage for Response {
    type Result = Result<(), RpcError>;
}

pub struct Miner {
    first_seen: u128, // timestamp of first connection
    key: PublicKey, // public key of account (address)
    name: String, // worker name
    blocks_found: usize, // blocks found since he is connected
}

impl Miner {
    pub fn new(key: PublicKey, name: String) -> Self {
        Self {
            first_seen: get_current_timestamp(),
            key,
            name,
            blocks_found: 0
        }
    }

    pub fn first_seen(&self) -> u128 {
        self.first_seen
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
        ctx.text(json!(msg).to_string());
        Ok(())
    }
}

pub struct GetWorkServer {
    miners: Mutex<HashMap<Addr<GetWorkWebSocketHandler>, Miner>>,
    blockchain: Arc<Blockchain>
}

impl GetWorkServer {
    pub fn new(blockchain: Arc<Blockchain>) -> Self {
        Self {
            miners: Mutex::new(HashMap::new()),
            blockchain
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
        let (mut block, difficulty) = {
            let storage = self.blockchain.get_storage().read().await;
            let block = self.blockchain.get_block_template(self.blockchain.get_dev_address().clone()).await?;
            let difficulty = self.blockchain.get_difficulty_at_tips(&storage, block.get_tips()).await?;
            (block, difficulty)
        };
        let miners = self.miners.lock().await;
        let mut extra_nonces = [0u8; EXTRA_NONCE_SIZE];
        for (addr, miner) in miners.iter() {
            let addr = addr.clone();
            OsRng.fill_bytes(&mut extra_nonces);
            block.set_miner(miner.get_public_key().clone());
            block.set_extra_nonce(extra_nonces);
            let template = block.to_hex();
            tokio::spawn(async move {
                match addr.send(Response::NewJob(GetBlockTemplateResult { template, difficulty })).await {
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