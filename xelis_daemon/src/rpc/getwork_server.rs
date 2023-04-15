use std::{sync::Arc, collections::HashMap, fmt::Display, borrow::Cow};
use actix::{Actor, AsyncContext, Handler, Message as TMessage, StreamHandler, Addr};
use actix_web_actors::ws::{ProtocolError, Message, WebsocketContext};
use anyhow::Context;
use log::{debug, warn, error};
use lru::LruCache;
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use serde_json::json;
use tokio::sync::Mutex;
use xelis_common::{crypto::{key::PublicKey, hash::Hash}, globals::get_current_timestamp, api::daemon::{GetBlockTemplateResult, SubmitBlockParams}, serializer::Serializer, block::{BlockHeader, BlockMiner, Difficulty}, config::{DEV_PUBLIC_KEY, STABLE_LIMIT}, immutable::Immutable, rpc_server::{RpcResponseError, InternalRpcError}};
use crate::core::{blockchain::Blockchain, storage::Storage};

pub type SharedGetWorkServer<S> = Arc<GetWorkServer<S>>;

#[derive(Serialize, PartialEq)]
pub enum Response {
    NewJob(GetBlockTemplateResult),
    BlockAccepted,
    BlockRejected
}

impl TMessage for Response {
    type Result = Result<(), InternalRpcError>;
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

pub struct GetWorkWebSocketHandler<S: Storage> {
    server: SharedGetWorkServer<S>
}

impl<S: Storage> GetWorkWebSocketHandler<S> {
    pub fn new(server: SharedGetWorkServer<S>) -> Self {
        Self {
            server
        }
    }
}

impl<S: Storage> Actor for GetWorkWebSocketHandler<S> {
    type Context = WebsocketContext<Self>;
}

impl<S: Storage> StreamHandler<Result<Message, ProtocolError>> for GetWorkWebSocketHandler<S> {
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
                let error = RpcResponseError::new(None, InternalRpcError::InvalidRequest);
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

impl<S: Storage> Handler<Response> for GetWorkWebSocketHandler<S> {
    type Result = Result<(), InternalRpcError>;

    fn handle(&mut self, msg: Response, ctx: &mut Self::Context) -> Self::Result {
        ctx.text(json!(msg).to_string());
        Ok(())
    }
}

pub struct GetWorkServer<S: Storage> {
    miners: Mutex<HashMap<Addr<GetWorkWebSocketHandler<S>>, Miner>>,
    blockchain: Arc<Blockchain<S>>,
    // all potential jobs sent to miners
    // we can keep them in cache up to STABLE_LIMIT blocks
    // so even a late miner have a chance to not be orphaned and be included in chain
    mining_jobs: Mutex<LruCache<Hash, (BlockHeader, Difficulty)>>,
    last_header_hash: Mutex<Option<Hash>>
}

impl<S: Storage> GetWorkServer<S> {
    pub fn new(blockchain: Arc<Blockchain<S>>) -> Self {
        Self {
            miners: Mutex::new(HashMap::new()),
            blockchain,
            mining_jobs: Mutex::new(LruCache::new(STABLE_LIMIT as usize)),
            last_header_hash: Mutex::new(None)
        }
    }

    pub async fn count_miners(&self) -> usize {
        self.miners.lock().await.len()
    }

    // retrieve last mining job and set random extra nonce and miner public key
    // then, send it
    async fn send_new_job(self: Arc<Self>, addr: Addr<GetWorkWebSocketHandler<S>>, key: PublicKey) -> Result<(), InternalRpcError> {
        let (mut job, height, difficulty) = {
            let mut mining_jobs = self.mining_jobs.lock().await;
            let mut hash = self.last_header_hash.lock().await;
            let (job, height, difficulty);
            if let Some(hash) = hash.as_ref() {
                let (header, diff) = mining_jobs.peek(hash).ok_or_else(|| {
                    error!("No mining job found! How is it possible ?");
                    InternalRpcError::InvalidRequest
                })?;
                job = BlockMiner::new(header.get_work_hash(), get_current_timestamp());
                height = header.height;
                difficulty = *diff;
            } else {
                // generate a mining job
                let storage = self.blockchain.get_storage().read().await;
                let header = self.blockchain.get_block_template_for_storage(&storage, DEV_PUBLIC_KEY.clone()).await.context("Error while retrieving block template")?;
                difficulty = self.blockchain.get_difficulty_at_tips(&*storage, header.get_tips()).await.context("Error while retrieving difficulty at tips")?;

                job = BlockMiner::new(header.get_work_hash(), get_current_timestamp());
                height = header.height;

                // save the mining job, and set it as last job
                *hash = Some(job.header_work_hash.clone());
                mining_jobs.put(job.header_work_hash.clone(), (header, difficulty));
            }

            (job, height, difficulty)
        };

        // set miner key and random extra nonce
        job.miner = Some(Cow::Owned(key));
        OsRng.fill_bytes(&mut job.extra_nonce);

        debug!("Sending job to new miner");
        addr.send(Response::NewJob(GetBlockTemplateResult { template: job.to_hex(), height, difficulty })).await.context("error while sending block template")??;
        Ok(())
    }

    pub async fn add_miner(self: &Arc<Self>, addr: Addr<GetWorkWebSocketHandler<S>>, key: PublicKey, worker: String) {
        {
            let mut miners = self.miners.lock().await;
            let miner = Miner::new(key.clone(), worker);
            debug!("Adding new miner to GetWork server: {}", miner);
            miners.insert(addr.clone(), miner);
        }

        // notify the new miner so he can work ASAP
        let zelf = Arc::clone(&self);
        tokio::spawn(zelf.send_new_job(addr, key));
    }

    pub async fn delete_miner(&self, addr: &Addr<GetWorkWebSocketHandler<S>>) {
        debug!("Trying to delete miner...");
        let mut miners = self.miners.lock().await;
        if let Some(miner) = miners.remove(addr) {
            debug!("{} deleted", miner);
        }
    }

    // this function is called when a miner send a new block
    // we retrieve the block header saved in cache using the mining job "header_work_hash"
    // its used to check that the job come from our server
    // when it's found, we merge the miner job inside the block header
    async fn accept_miner_job(&self, job: BlockMiner<'_>) -> Result<Response, InternalRpcError> {
        if job.miner.is_none() {
            return Err(InternalRpcError::InvalidRequest);
        }

        let mut miner_header;
        {
            let mining_jobs = self.mining_jobs.lock().await;
            if let Some((header, _)) = mining_jobs.peek(&job.header_work_hash) {
                // job is found in cache, clone it and put miner data inside
                miner_header = header.clone();
                miner_header.nonce = job.nonce;
                miner_header.extra_nonce = job.extra_nonce;
                miner_header.set_miner(job.miner.ok_or(InternalRpcError::InvalidRequest)?.into_owned());
                miner_header.timestamp = job.timestamp;
            } else {
                // really old job, or miner send invalid job
                debug!("Job {} was not found in cache", job.header_work_hash);
                return Err(InternalRpcError::InvalidRequest)
            };
        }

        let block = self.blockchain.build_block_from_header(Immutable::Owned(miner_header)).await.context("Error while building block from header")?;
        Ok(match self.blockchain.add_new_block(block, true).await {
            Ok(_) => Response::BlockAccepted,
            Err(e) => {
                debug!("Error while accepting miner block: {}", e);
                Response::BlockRejected
            }
        })
    }

    // handle the incoming mining job from the miner
    // decode the block miner, and using its header work hash, retrieve the block header
    // if its block is rejected, resend him the job
    pub async fn handle_block_for(self: Arc<Self>, addr: Addr<GetWorkWebSocketHandler<S>>, template: SubmitBlockParams) -> Result<(), InternalRpcError> {
        let job = BlockMiner::from_hex(template.block_template)?;
        let response = self.accept_miner_job(job).await?;

        tokio::spawn(async move {
            let resend_job = response == Response::BlockRejected;
            debug!("Sending response to the miner");
            if let Err(e) = addr.send(response).await {
                error!("Error while sending block rejected response: {}", e);
            }

            if resend_job {
                debug!("Resending job to the miner");
                let key = {
                    let miners = self.miners.lock().await;
                    if let Some(miner) = miners.get(&addr) {
                        Some(miner.get_public_key().clone())
                    } else {
                        error!("Miner not found in the list of miners! (should not happen)");
                        None
                    }
                };
                if let Some(key) = key {
                    if let Err(e) = self.send_new_job(addr, key).await {
                        error!("Error while sending new job to miner: {}", e);
                    };
                }
            }
            debug!("Response sent!");
        });

        Ok(())
    }

    // notify every miners connected to the getwork server
    // each miner have his own task so nobody wait on other
    pub async fn notify_new_job(&self) -> Result<(), InternalRpcError> {        
        debug!("Notify all miners for a new job");
        let (header, difficulty) = {
            let storage = self.blockchain.get_storage().read().await;
            let header = self.blockchain.get_block_template_for_storage(&storage, DEV_PUBLIC_KEY.clone()).await.context("Error while retrieving block template when notifying new job")?;
            let difficulty = self.blockchain.get_difficulty_at_tips(&*storage, header.get_tips()).await.context("Error while retrieving difficulty at tips when notifying new job")?;
            (header, difficulty)
        };

        let mut job = BlockMiner::new(header.get_work_hash(), header.timestamp);
        let height = header.height;

        // save the header used for job in cache
        {
            let mut last_header_hash = self.last_header_hash.lock().await;
            *last_header_hash = Some(job.header_work_hash.clone());
            let mut mining_jobs = self.mining_jobs.lock().await;
            mining_jobs.put(job.header_work_hash.clone(), (header, difficulty));
        }

        // now let's send the job to every miner
        let miners = self.miners.lock().await;
        for (addr, miner) in miners.iter() {
            debug!("Notifying {} for new job", miner);
            let addr = addr.clone();

            job.miner = Some(Cow::Borrowed(miner.get_public_key()));
            OsRng.fill_bytes(&mut job.extra_nonce);
            let template = job.to_hex();

            tokio::spawn(async move {
                match addr.send(Response::NewJob(GetBlockTemplateResult { template, height, difficulty })).await {
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