use std::{sync::Arc, collections::HashMap, fmt::Display};
use actix::{Actor, AsyncContext, Handler, Message as TMessage, StreamHandler, Addr};
use actix_web_actors::ws::{ProtocolError, Message, WebsocketContext};
use anyhow::Context;
use log::{debug, warn, error};
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use serde_json::json;
use tokio::sync::Mutex;
use xelis_common::{crypto::key::PublicKey, globals::get_current_timestamp, api::daemon::{GetBlockTemplateResult, SubmitBlockParams}, serializer::Serializer, block::{EXTRA_NONCE_SIZE, Block}};
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

impl Display for Miner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Miner[address={}, name={}]", self.key.to_address(), self.name)        
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
                debug!("New message incoming from miner");
                let address = ctx.address();
                let template: SubmitBlockParams = match serde_json::from_slice(text.as_bytes()) {
                    Ok(template) => template,
                    Err(e) => {
                        debug!("Error while decoding message from {:?}: {}", address, e);
                        return;
                    }
                };

                let server = self.server.clone();
                let fut = async move {
                    if let Err(e) = server.handle_block_for(address, template).await {
                        debug!("Error while handling new job from miner: {}", e);
                    }
                };
                ctx.wait(actix::fut::wrap_future(fut));
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
        debug!("miner has disconnected");
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

    pub async fn count_miners(&self) -> usize {
        self.miners.lock().await.len()
    }

    pub async fn add_miner(self: &Arc<Self>, addr: Addr<GetWorkWebSocketHandler>, key: PublicKey, worker: String) {
        {
            let mut miners = self.miners.lock().await;
            let miner = Miner::new(key.clone(), worker);
            debug!("Adding new miner to GetWork server: {}", miner);
            miners.insert(addr.clone(), miner);
        }

        // notify the new miner so he can work ASAP
        let blockchain = Arc::clone(&self.blockchain);
        tokio::spawn(async move {
            let (template, difficulty) = {
                let storage = blockchain.get_storage().read().await;
                let block = match blockchain.get_block_template_for_storage(&storage, key).await {
                    Ok(block) => block,
                    Err(e) => {
                        error!("Error while generating block template: {}", e);
                        return;
                    }
                };
                let difficulty = match blockchain.get_difficulty_at_tips(&storage, block.get_tips()).await {
                    Ok(difficulty) => difficulty,
                    Err(e) => {
                        error!("Error while calculating difficulty at tips for block template: {}", e);
                        return;
                    }
                };
                (block.to_hex(), difficulty)
            };
            debug!("Sending job to new miner");
            if let Err(e) = addr.send(Response::NewJob(GetBlockTemplateResult { template, difficulty })).await {
                error!("Error while sending new job to new miner: {}", e);
            }
        });
    }

    pub async fn delete_miner(&self, addr: &Addr<GetWorkWebSocketHandler>) {
        debug!("Trying to delete miner...");
        let mut miners = self.miners.lock().await;
        if let Some(miner) = miners.remove(addr) {
            debug!("{} deleted", miner);
        }
    }

    pub async fn handle_block_for(&self, addr: Addr<GetWorkWebSocketHandler>, template: SubmitBlockParams) -> Result<(), RpcError> {
        let block = Block::from_hex(template.block_template)?;
        {
            let mut miners = self.miners.lock().await;
            let miner = miners.get_mut(&addr).context("Unregistered miner found, cannot handle this block")?;
            debug!("Handle job found by {} at height {}", miner, block.get_height());
        }

        let complete_block = self.blockchain.build_complete_block_from_block(block).await?;
        let response = match self.blockchain.add_new_block(complete_block, true).await {
            Ok(_) => Response::BlockAccepted,
            Err(e) => {
                debug!("Error while accepting miner block: {}", e);
                Response::BlockRejected
            }
        };

        tokio::spawn(async move {
            debug!("Sending response to the miner");
            if let Err(e) = addr.send(response).await {
                error!("Error while sending block rejected response: {}", e);
            }
            debug!("Response sent!");
        });

        Ok(())
    }

    // notify every miners connected to the getwork server
    // each miner have his own task so nobody wait on other
    pub async fn notify_new_job(&self) -> Result<(), RpcError> {        
        debug!("Notify all miners for a new job");
        let (mut block, difficulty) = {
            let storage = self.blockchain.get_storage().read().await;
            let block = self.blockchain.get_block_template_for_storage(&storage, self.blockchain.get_dev_address().clone()).await?;
            let difficulty = self.blockchain.get_difficulty_at_tips(&storage, block.get_tips()).await?;
            (block, difficulty)
        };
        let miners = self.miners.lock().await;
        let mut extra_nonces = [0u8; EXTRA_NONCE_SIZE];
        for (addr, miner) in miners.iter() {
            debug!("Notifying {} for new job", miner);
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