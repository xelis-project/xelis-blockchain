mod miner;

use std::{
    borrow::Cow, collections::HashMap, num::NonZeroUsize, sync::{
        atomic::{
            AtomicBool,
            AtomicU64, Ordering
        },
        Arc
    }, time::Duration
};
use bytes::Bytes;
use futures::{stream, StreamExt};
use rand::{rngs::OsRng, RngCore};
use actix_web::HttpResponse;
use anyhow::Context;
use async_trait::async_trait;
use log::{debug, error, trace, warn};
use lru::LruCache;
use serde::Serialize;
use tokio::{sync::Mutex, time::sleep};
use xelis_common::{
    api::daemon::{
        GetBlockTemplateResult,
        GetMinerWorkResult,
        NotifyEvent,
        SubmitMinerWorkParams
    },
    block::{BlockHeader, MinerWork},
    config::TIPS_LIMIT,
    crypto::{
        Address,
        Hash,
        Hashable,
        PublicKey
    },
    difficulty::Difficulty,
    immutable::Immutable,
    rpc_server::{
        websocket::{WebSocketHandler, WebSocketSessionShared},
        InternalRpcError
    },
    serializer::Serializer,
    time::{get_current_time_in_millis, TimestampMillis},
    tokio::spawn_task
};
use crate::{
    config::{DEV_PUBLIC_KEY, STABLE_LIMIT},
    core::{blockchain::Blockchain,
        hard_fork::get_pow_algorithm_for_version,
        storage::Storage
    }
};

pub use miner::*;

#[derive(Serialize, PartialEq)]
#[serde(rename_all = "snake_case")] 
pub enum Response {
    NewJob(GetMinerWorkResult),
    BlockAccepted,
    BlockRejected(String)
}

pub enum BlockResult {
    Accepted(Arc<Hash>),
    Rejected(anyhow::Error)
}

pub type SharedGetWorkServer<S> = Arc<GetWorkServer<S>>;

pub struct GetWorkServer<S: Storage> {
    miners: Mutex<HashMap<WebSocketSessionShared<Self>, Miner>>,
    blockchain: Arc<Blockchain<S>>,
    // all potential jobs sent to miners
    // we can keep them in cache up to STABLE_LIMIT blocks
    // so even a late miner have a chance to not be orphaned and be included in chain
    mining_jobs: Mutex<LruCache<Hash, (BlockHeader, Difficulty)>>,
    last_header_hash: Mutex<Option<Hash>>,
    // used only when a new TX is received in mempool
    last_notify: AtomicU64,
    // used to know if we can notify miners again
    is_job_dirty: AtomicBool,
    // We can only notify miners every N ms when a new job is available
    // (When a new TX is received in mempool)
    // This is used to avoid flooding the miners with notifications
    // If the rate limit is set to 0, we can notify miners every time
    notify_rate_limit_ms: TimestampMillis,
    // Current limit for the number of miners to notify at the same time
    notify_job_concurrency: usize,
}

impl<S: Storage> GetWorkServer<S> {
    pub fn new(blockchain: Arc<Blockchain<S>>, notify_rate_limit_ms: TimestampMillis, notify_job_concurrency: usize) -> Arc<Self> {
        let server = Arc::new(Self {
            miners: Mutex::new(HashMap::new()),
            blockchain,
            mining_jobs: Mutex::new(LruCache::new(NonZeroUsize::new(STABLE_LIMIT as usize * TIPS_LIMIT).expect("Non zero mining jobs cache"))),
            last_header_hash: Mutex::new(None),
            last_notify: AtomicU64::new(0),
            is_job_dirty: AtomicBool::new(false),
            notify_rate_limit_ms,
            notify_job_concurrency
        });

        if notify_rate_limit_ms > 0 {
            let zelf = Arc::clone(&server);
            spawn_task("getwork-notifier", zelf.task_notifier());
        }

        server
    }

    // check if the last notify is older than the rate limit
    // if it's the case, we can notify miners
    // Returns a tuple with a boolean indicating if the rate limit is reached, and the current timestamp
    fn is_rate_limited(&self) -> bool {
        let now = get_current_time_in_millis();
        let last_notify = self.last_notify.load(Ordering::SeqCst);
        now - last_notify < self.notify_rate_limit_ms
    }

    // notify every miners connected to the getwork server
    // each miner have his own task so nobody wait on other
    pub async fn notify_new_job_rate_limited(&self) -> Result<(), InternalRpcError> {
        let rate_limit_reached = self.is_rate_limited();
        if rate_limit_reached {
            debug!("Rate limit reached, no need to notify miners");
            self.is_job_dirty.store(true, Ordering::SeqCst);
            return Ok(());
        }

        self.notify_new_job().await
    }

    // This function is used to notify miners every N ms
    // It will check if the job is dirty, and if so, it will notify miners
    // This is used to avoid flooding the miners with notifications
    async fn task_notifier(self: Arc<Self>) {
        loop {
            sleep(Duration::from_millis(self.notify_rate_limit_ms)).await;
            if self.is_job_dirty.load(Ordering::SeqCst) {
                debug!("job is dirty, resending job to all miners");
                if let Err(e) = self.notify_new_job().await {
                    error!("Error while notifying new job to miners: {}", e);
                }
            }
        }
    }

    // Returns the number of miners connected to the getwork server
    pub async fn count_miners(&self) -> usize {
        trace!("count miners");
        self.miners.lock().await.len()
    }

    // Returns the list of miners connected to the getwork server
    pub fn get_miners(&self) -> &Mutex<HashMap<WebSocketSessionShared<Self>, Miner>> {
        trace!("get miners");
        &self.miners
    }

    // retrieve last mining job and set random extra nonce and miner public key
    // then, send it
    async fn send_new_job(&self, session: &WebSocketSessionShared<Self>, key: &PublicKey) -> Result<(), anyhow::Error> {
        debug!("Sending new job to miner");
        let (mut job, version, height, difficulty) = {
            let mut hash = self.last_header_hash.lock().await;
            let mut mining_jobs = self.mining_jobs.lock().await;
            let (version, job, height, difficulty);
            // if we have a job in cache, and we are rate limited, we can send it
            // otherwise, we generate a new job
            if let Some(hash) = hash.as_ref().filter(|_| self.is_rate_limited()) {
                let (header, diff) = mining_jobs.peek(hash).ok_or_else(|| {
                    error!("No mining job found! How is it possible ?");
                    InternalRpcError::InternalError("No mining job found")
                })?;
                job = MinerWork::new(header.get_work_hash(), get_current_time_in_millis());
                height = header.get_height();
                version = header.get_version();
                difficulty = *diff;
            } else {
                // generate a mining job
                let storage = self.blockchain.get_storage().read().await;
                let header = self.blockchain.get_block_template_for_storage(&storage, DEV_PUBLIC_KEY.clone()).await
                    .context("Error while retrieving block template")?;
                (difficulty, _) = self.blockchain.get_difficulty_at_tips(&*storage, header.get_tips().iter()).await
                    .context("Error while retrieving difficulty at tips")?;

                job = MinerWork::new(header.get_work_hash(), get_current_time_in_millis());
                height = header.get_height();
                version = header.get_version();

                // save the mining job, and set it as last job
                let header_work_hash = job.get_header_work_hash();
                *hash = Some(header_work_hash.clone());
                mining_jobs.put(header_work_hash.clone(), (header, difficulty));
            }

            (job, version, height, difficulty)
        };

        // set miner key and random extra nonce
        job.set_miner(Cow::Borrowed(key));
        OsRng.fill_bytes(job.get_extra_nonce());

        // get the algorithm for the current version
        let algorithm = get_pow_algorithm_for_version(version);
        let topoheight = self.blockchain.get_topo_height();

        debug!("Sending job to new miner");
        session.send_json(Response::NewJob(GetMinerWorkResult { algorithm, miner_work: job.to_hex(), height, topoheight, difficulty })).await
            .context("error while sending block template")?;
        debug!("Job sent to miner");

        Ok(())
    }

    // notify every miners connected to the getwork server
    // each miner have his own task so nobody wait on other
    pub async fn notify_new_job(&self) -> Result<(), InternalRpcError> {
        trace!("notify new job");
        // Check that there is at least one miner connected
        // otherwise, no need to build a new job
        let is_event_tracked = {
            if let Some(rpc) = self.blockchain.get_rpc().read().await.as_ref() {
                rpc.get_tracked_events().await
                    .contains(&NotifyEvent::NewBlockTemplate)
            } else {
                false
            }
        };

        let miners_empty = {
            let miners = self.miners.lock().await;
            let empty =  miners.is_empty();
            if empty && !is_event_tracked {
                debug!("No miners connected, no need to notify them");
                return Ok(());
            }
            empty
        };

        self.last_notify.store(get_current_time_in_millis(), Ordering::SeqCst);
        self.is_job_dirty.store(false, Ordering::SeqCst);
        debug!("Notify all miners for a new job");
        let (header, difficulty) = {
            let storage = self.blockchain.get_storage().read().await;
            let header = self.blockchain.get_block_template_for_storage(&storage, DEV_PUBLIC_KEY.clone()).await
                .context("Error while retrieving block template when notifying new job")?;
            let (difficulty, _) = self.blockchain.get_difficulty_at_tips(&*storage, header.get_tips().iter()).await
                .context("Error while retrieving difficulty at tips when notifying new job")?;
            (header, difficulty)
        };

        let job = MinerWork::new(header.get_work_hash(), header.timestamp);
        let height = header.get_height();
        let version = header.get_version();

        // get the algorithm for the current version
        let algorithm = get_pow_algorithm_for_version(version);
        // Also send the node topoheight to miners
        // This is for visual purposes only
        let topoheight = self.blockchain.get_topo_height();

        if is_event_tracked {
            let rpc = self.blockchain.get_rpc().read().await;
            if let Some(rpc) = rpc.as_ref() {
                let value = GetBlockTemplateResult {
                    template: header.to_hex(),
                    algorithm,
                    height,
                    topoheight,
                    difficulty
                };

                rpc.notify_clients_with(&NotifyEvent::NewBlockTemplate, value).await;
            }
        }

        // save the header used for job in cache
        {
            let header_work_hash = job.get_header_work_hash();
            let mut last_header_hash = self.last_header_hash.lock().await;
            *last_header_hash = Some(header_work_hash.clone());
            let mut mining_jobs = self.mining_jobs.lock().await;
            mining_jobs.put(header_work_hash.clone(), (header, difficulty));
        }

        if !miners_empty {
            // now let's send the job to every miner
            let miners = self.miners.lock().await;

            debug!("Notifying {} miners for new job", miners.len());
            stream::iter(miners.iter())
                .for_each_concurrent(self.notify_job_concurrency, |(addr, miner)| {
                    let mut job = job.clone();
                    async move {
                        debug!("Notifying {} for new job", miner);
                        let addr = addr.clone();

                        job.set_miner(Cow::Borrowed(miner.get_public_key()));
                        OsRng.fill_bytes(job.get_extra_nonce());
                        let template = job.to_hex();

                        if let Err(e) = addr.send_json(Response::NewJob(GetMinerWorkResult { algorithm, miner_work: template, height, topoheight, difficulty })).await {
                            warn!("Error while notifying {} about new job: {}", miner, e);
                        }
                    }
                }).await;
        }

        debug!("job has been shared!");

        Ok(())
    }

    // this function is called when a miner send a new block
    // we retrieve the block header saved in cache using the mining job "header_work_hash"
    // its used to check that the job come from our server
    // when it's found, we merge the miner job inside the block header
    async fn accept_miner_job(&self, job: MinerWork<'_>) -> Result<BlockResult, InternalRpcError> {
        trace!("accept miner job");
        if job.get_miner().is_none() {
            return Err(InternalRpcError::InvalidJSONRequest);
        }

        let mut miner_header;
        {
            let mining_jobs = self.mining_jobs.lock().await;
            if let Some((header, _)) = mining_jobs.peek(job.get_header_work_hash()) {
                // job is found in cache, clone it and put miner data inside
                miner_header = header.clone();
                miner_header.apply_miner_work(job);
            } else {
                // really old job, or miner send invalid job
                debug!("Job {} was not found in cache", job.get_header_work_hash());
                return Err(InternalRpcError::InvalidParams("Job was not found in cache"))
            };
        }

        let block = self.blockchain.build_block_from_header(Immutable::Owned(miner_header)).await
            .context("Error while building block from header")?;
        let block_hash = Arc::new(block.hash());

        Ok(match self.blockchain.add_new_block(block, Some(Immutable::Arc(block_hash.clone())), true, true).await {
            Ok(_) => BlockResult::Accepted(block_hash),
            Err(e) => {
                debug!("Error while accepting miner block: {}", e);
                BlockResult::Rejected(e.into())
            }
        })
    }

    // handle the incoming mining job from the miner
    // decode the block miner, and using its header work hash, retrieve the block header
    // if its block is rejected, resend him the job
    pub async fn handle_block_for(&self, session: &WebSocketSessionShared<Self>, submitted_work: SubmitMinerWorkParams) -> Result<(), anyhow::Error> {
        trace!("handle block for");
        let result = match MinerWork::from_hex(&submitted_work.miner_work) {
            Ok(job) => match self.accept_miner_job(job).await {
                Ok(result) => result,
                Err(e) => {
                    debug!("Error while accepting miner job: {}", e);
                    BlockResult::Rejected(e.into())
                }
            },
            Err(e) => {
                debug!("Error while decoding block miner: {}", e);
                BlockResult::Rejected(e.into())
            }
        };

        // update miner stats
        debug!("locking miners to update miner stats");
        let mut miners = self.miners.lock().await;
        debug!("miners locked for miner stats");
        let miner = miners.get_mut(session)
            .context("Miner not found in cache")?;

        match result {
            BlockResult::Accepted(hash) => {
                debug!("Miner {} found block {}!", miner, hash);
                miner.add_new_accepted_block(hash);

                session.send_json(Response::BlockAccepted).await?;
            },
            BlockResult::Rejected(err) => {
                debug!("Miner {} sent an invalid block", miner);
                miner.mark_rejected_block();

                session.send_json(Response::BlockRejected(err.to_string())).await?;
                self.send_new_job(session, miner.get_public_key()).await?;
            }
        };

        Ok(())
    }
}

#[async_trait]
impl<S: Storage> WebSocketHandler for GetWorkServer<S> {
    // For retro-compatibility with older miner versions,
    // we don't send any ping
    fn send_ping_interval(&self) -> Option<Duration> {
        None
    }

    async fn on_connection(&self, session: &WebSocketSessionShared<Self>) -> Result<Option<actix_web::HttpResponse>, anyhow::Error> {
        let path = session.get_request().uri().path();
        let parts: Vec<_> = path.split("/").collect();

        // "" / "getwork" / "addr" / "worker"
        if parts.len() != 4 {
            return Ok(Some(HttpResponse::BadRequest().body("Missing address and/or worker name")))
        }

        let addr = parts[2];
        let worker = parts[3];
        if worker.len() > 32 {
            return Ok(Some(HttpResponse::BadRequest().body("Worker name must be less or equal to 32 chars")))
        }

        let address: Address = match Address::from_string(&addr) {
            Ok(address) => address,
            Err(e) => {
                debug!("Invalid miner address for getwork server: {}", e);
                return Ok(Some(HttpResponse::BadRequest().body("Invalid miner address for getwork server")))
            }
        };
        if !address.is_normal() {
            return Ok(Some(HttpResponse::BadRequest().body("Address should be in normal format")))
        }

        let network = self.blockchain.get_network();
        if address.is_mainnet() != network.is_mainnet() {
            return Ok(Some(HttpResponse::BadRequest().body(format!("Address is not in same network state, should be in {} mode", network.to_string().to_lowercase()))))
        }

        let key = address.to_public_key();

        // We can directly send it here as it's buffered by the channel
        debug!("trying to send initial job to new miner");
        self.send_new_job(session, &key).await?;
        debug!("initial job has been sent");

        {
            let mut miners = self.miners.lock().await;
            miners.insert(session.clone(), Miner::new(network.is_mainnet(), key.clone(), worker.to_owned()));
        }

        debug!("miner has been added in miners list");

        Ok(None)
    }

    // called when a new message is received
    async fn on_message(&self, session: &WebSocketSessionShared<Self>, body: Bytes) -> Result<(), anyhow::Error> {
        let submitted_work: SubmitMinerWorkParams = serde_json::from_slice(&body)?;
        self.handle_block_for(session, submitted_work).await
    }

    async fn on_close(&self, session: &WebSocketSessionShared<Self>) -> Result<(), anyhow::Error> {
        let mut miners = self.miners.lock().await;
        miners.remove(session);

        Ok(())
    }
}
