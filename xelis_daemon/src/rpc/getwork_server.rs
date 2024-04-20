use std::{
    borrow::Cow,
    collections::HashMap,
    fmt::Display,
    num::NonZeroUsize,
    sync::{
        atomic::{
            AtomicU64,
            Ordering
        },
        Arc
    }
};
use actix::{
    Actor,
    AsyncContext,
    Handler,
    Message as TMessage,
    StreamHandler,
    Addr
};
use actix_web_actors::ws::{
    ProtocolError,
    Message,
    WebsocketContext
};
use anyhow::Context;
use log::{debug, warn, error};
use lru::LruCache;
use rand::{
    rngs::OsRng,
    RngCore
};
use serde::Serialize;
use serde_json::json;
use tokio::sync::Mutex;
use xelis_common::{
    crypto::{
        PublicKey,
        Hash
    },
    time::{
        TimestampMillis,
        get_current_time_in_millis
    },
    api::daemon::{
        GetBlockTemplateResult,
        SubmitBlockParams
    },
    serializer::Serializer,
    block::{
        BlockHeader,
        BlockMiner
    },
    difficulty::Difficulty,
    immutable::Immutable,
    rpc_server::{
        RpcResponseError,
        InternalRpcError
    }
};
use crate::{
    core::{
        blockchain::Blockchain,
        storage::Storage
    },
    config::{
        DEV_PUBLIC_KEY,
        STABLE_LIMIT
    }
};

pub type SharedGetWorkServer<S> = Arc<GetWorkServer<S>>;

#[derive(Serialize, PartialEq)]
#[serde(rename_all = "snake_case")] 
pub enum Response {
    NewJob(GetBlockTemplateResult),
    BlockAccepted,
    BlockRejected(String)
}

impl TMessage for Response {
    type Result = Result<(), InternalRpcError>;
}

pub struct Miner {
    // Used to display correctly its address
    mainnet: bool,
    first_seen: TimestampMillis, // timestamp of first connection
    key: PublicKey, // public key of account (address)
    name: String, // worker name
    blocks_accepted: usize, // blocks accepted by us since he is connected
    blocks_rejected: usize // blocks rejected since he is connected
}

impl Miner {
    pub fn new(mainnet: bool, key: PublicKey, name: String) -> Self {
        Self {
            mainnet,
            first_seen: get_current_time_in_millis(),
            key,
            name,
            blocks_accepted: 0,
            blocks_rejected: 0
        }
    }

    pub fn first_seen(&self) -> u64 {
        self.first_seen
    }

    pub fn get_public_key(&self) -> &PublicKey {
        &self.key
    }

    pub fn get_name(&self) -> &String {
        &self.name
    }

    pub fn get_blocks_accepted(&self) -> usize {
        self.blocks_accepted
    }
}

impl Display for Miner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Miner[address={}, name={}, accepted={}, rejected={}]", self.key.as_address(self.mainnet), self.name, self.blocks_accepted, self.blocks_rejected)
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
                debug!("New message incoming from miner: {}", text);
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
    last_header_hash: Mutex<Option<Hash>>,
    // used only when a new TX is received in mempool
    last_notify: AtomicU64,
    notify_rate_limit_ms: u64
}

impl<S: Storage> GetWorkServer<S> {
    pub fn new(blockchain: Arc<Blockchain<S>>) -> Self {
        Self {
            miners: Mutex::new(HashMap::new()),
            blockchain,
            mining_jobs: Mutex::new(LruCache::new(NonZeroUsize::new(STABLE_LIMIT as usize).unwrap())),
            last_header_hash: Mutex::new(None),
            last_notify: AtomicU64::new(0),
            notify_rate_limit_ms: 500 // maximum one time every 500ms
        }
    }

    // Returns the number of miners connected to the getwork server
    pub async fn count_miners(&self) -> usize {
        self.miners.lock().await.len()
    }

    // Returns the list of miners connected to the getwork server
    pub fn get_miners(&self) -> &Mutex<HashMap<Addr<GetWorkWebSocketHandler<S>>, Miner>> {
        &self.miners
    }

    // retrieve last mining job and set random extra nonce and miner public key
    // then, send it
    async fn send_new_job(self: Arc<Self>, addr: Addr<GetWorkWebSocketHandler<S>>, key: PublicKey) -> Result<(), InternalRpcError> {
        let (mut job, height, difficulty) = {
            let mut hash = self.last_header_hash.lock().await;
            let mut mining_jobs = self.mining_jobs.lock().await;
            let (job, height, difficulty);
            // if we have a job in cache, and we are rate limited, we can send it
            // otherwise, we generate a new job
            if let Some(hash) = hash.as_ref().filter(|_| self.is_rate_limited().0) {
                let (header, diff) = mining_jobs.peek(hash).ok_or_else(|| {
                    error!("No mining job found! How is it possible ?");
                    InternalRpcError::CustomStr("No mining job found")
                })?;
                job = BlockMiner::new(header.get_work_hash(), get_current_time_in_millis());
                height = header.height;
                difficulty = *diff;
            } else {
                // generate a mining job
                let storage = self.blockchain.get_storage().read().await;
                let header = self.blockchain.get_block_template_for_storage(&storage, DEV_PUBLIC_KEY.clone()).await.context("Error while retrieving block template")?;
                (difficulty, _) = self.blockchain.get_difficulty_at_tips(&*storage, header.get_tips().iter()).await.context("Error while retrieving difficulty at tips")?;

                job = BlockMiner::new(header.get_work_hash(), get_current_time_in_millis());
                height = header.height;

                // save the mining job, and set it as last job
                let header_work_hash = job.get_header_work_hash();
                *hash = Some(header_work_hash.clone());
                mining_jobs.put(header_work_hash.clone(), (header, difficulty));
            }

            (job, height, difficulty)
        };

        // set miner key and random extra nonce
        job.set_miner(Cow::Owned(key));
        OsRng.fill_bytes(job.get_extra_nonce());

        debug!("Sending job to new miner");
        addr.send(Response::NewJob(GetBlockTemplateResult { template: job.to_hex(), height, difficulty })).await.context("error while sending block template")??;
        Ok(())
    }

    pub async fn add_miner(self: &Arc<Self>, addr: Addr<GetWorkWebSocketHandler<S>>, key: PublicKey, worker: String) {
        {
            let mut miners = self.miners.lock().await;
            let miner = Miner::new(self.blockchain.get_network().is_mainnet(), key.clone(), worker);
            debug!("Adding new miner to GetWork server: {}", miner);
            miners.insert(addr.clone(), miner);
        }

        // notify the new miner so he can work ASAP
        let zelf = Arc::clone(&self);
        tokio::spawn(async move {
            if let Err(e) = zelf.send_new_job(addr, key).await {
                error!("Error while sending new job to miner: {}", e);
            }
        });
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
        if job.get_miner().is_none() {
            return Err(InternalRpcError::InvalidRequest);
        }

        let mut miner_header;
        {
            let mining_jobs = self.mining_jobs.lock().await;
            if let Some((header, _)) = mining_jobs.peek(job.get_header_work_hash()) {
                // job is found in cache, clone it and put miner data inside
                miner_header = header.clone();
                let (_, timestamp, nonce, miner, extra_nonce) = job.take();
                miner_header.nonce = nonce;
                miner_header.extra_nonce = extra_nonce;
                miner_header.set_miner(miner.ok_or(InternalRpcError::InvalidRequest)?.into_owned());
                miner_header.timestamp = timestamp;
            } else {
                // really old job, or miner send invalid job
                debug!("Job {} was not found in cache", job.get_header_work_hash());
                return Err(InternalRpcError::CustomStr("Job was not found in cache"))
            };
        }

        let block = self.blockchain.build_block_from_header(Immutable::Owned(miner_header)).await.context("Error while building block from header")?;
        Ok(match self.blockchain.add_new_block(block, true, true).await {
            Ok(_) => Response::BlockAccepted,
            Err(e) => {
                debug!("Error while accepting miner block: {}", e);
                Response::BlockRejected(e.to_string())
            }
        })
    }

    // handle the incoming mining job from the miner
    // decode the block miner, and using its header work hash, retrieve the block header
    // if its block is rejected, resend him the job
    pub async fn handle_block_for(self: Arc<Self>, addr: Addr<GetWorkWebSocketHandler<S>>, template: SubmitBlockParams) -> Result<(), InternalRpcError> {
        let job = BlockMiner::from_hex(template.block_template)?;
        let response = match self.accept_miner_job(job).await {
            Ok(response) => response,
            Err(e) => {
                debug!("Error while accepting miner job: {}", e);
                Response::BlockRejected(e.to_string())
            }
        };

        // update miner stats
        {
            let mut miners = self.miners.lock().await;
            if let Some(miner) = miners.get_mut(&addr) {
                match &response {
                    Response::BlockAccepted => {
                        debug!("Miner {} found a block!", miner);
                        miner.blocks_accepted += 1;
                    },
                    Response::BlockRejected(_) => {
                        debug!("Miner {} sent an invalid block", miner);
                        miner.blocks_rejected += 1;
                    },
                    _ => {}
                }
            }
        }

        tokio::spawn(async move {
            let resend_job = match response {
                Response::BlockRejected(_) => true,
                _ => false
            };
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

    // check if the last notify is older than the rate limit
    // if it's the case, we can notify miners
    // Returns a tuple with a boolean indicating if the rate limit is reached, and the current timestamp
    fn is_rate_limited(&self) -> (bool, TimestampMillis) {
        let now = get_current_time_in_millis();
        let last_notify = self.last_notify.load(Ordering::SeqCst);
        (now - last_notify < self.notify_rate_limit_ms, now)
    }

    // notify every miners connected to the getwork server
    // each miner have his own task so nobody wait on other
    pub async fn notify_new_job_rate_limited(&self) -> Result<(), InternalRpcError> {
        let (rate_limit_reached, now) = self.is_rate_limited();
        if rate_limit_reached {
            debug!("Rate limit reached, no need to notify miners");
            return Ok(());
        }
        self.last_notify.store(now, Ordering::SeqCst);

        self.notify_new_job().await
    }

    // notify every miners connected to the getwork server
    // each miner have his own task so nobody wait on other
    pub async fn notify_new_job(&self) -> Result<(), InternalRpcError> {
        // Check that there is at least one miner connected
        // otherwise, no need to build a new job
        {
            let miners = self.miners.lock().await;
            if miners.is_empty() {
                debug!("No miners connected, no need to notify them");
                return Ok(());
            }
        }
    
        debug!("Notify all miners for a new job");
        let (header, difficulty) = {
            let storage = self.blockchain.get_storage().read().await;
            let header = self.blockchain.get_block_template_for_storage(&storage, DEV_PUBLIC_KEY.clone()).await.context("Error while retrieving block template when notifying new job")?;
            let (difficulty, _) = self.blockchain.get_difficulty_at_tips(&*storage, header.get_tips().iter()).await.context("Error while retrieving difficulty at tips when notifying new job")?;
            (header, difficulty)
        };

        let mut job = BlockMiner::new(header.get_work_hash(), header.timestamp);
        let height = header.height;

        // save the header used for job in cache
        {
            let header_work_hash = job.get_header_work_hash();
            let mut last_header_hash = self.last_header_hash.lock().await;
            *last_header_hash = Some(header_work_hash.clone());
            let mut mining_jobs = self.mining_jobs.lock().await;
            mining_jobs.put(header_work_hash.clone(), (header, difficulty));
        }

        // now let's send the job to every miner
        let mut miners = self.miners.lock().await;
        miners.retain(|addr, _| addr.connected());

        for (addr, miner) in miners.iter() {
            debug!("Notifying {} for new job", miner);
            let addr = addr.clone();

            job.set_miner(Cow::Borrowed(miner.get_public_key()));
            OsRng.fill_bytes(job.get_extra_nonce());
            let template = job.to_hex();

            // New task for each miner in case a miner is slow
            // we don't want to wait for him
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