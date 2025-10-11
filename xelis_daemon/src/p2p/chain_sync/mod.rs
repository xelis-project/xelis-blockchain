mod bootstrap;
mod chain_validator;

use std::{
    borrow::Cow,
    sync::Arc,
    time::{Duration, Instant}
};
use futures::{
    stream,
    StreamExt,
};
use indexmap::IndexSet;
use log::{debug, error, info, trace, warn};
use xelis_common::{
    block::{Block, BlockVersion},
    crypto::Hash,
    immutable::Immutable,
    time::{get_current_time_in_millis, TimestampMillis},
    tokio::{
        select,
        time::interval,
        sync::Mutex,
        Executor,
        Scheduler
    },
    transaction::Transaction
};

use crate::{
    config::{CHAIN_SYNC_TOP_BLOCKS, PEER_OBJECTS_CONCURRENCY, STABLE_LIMIT},
    core::{
        blockchain::{BroadcastOption, PreVerifyBlock},
        error::BlockchainError,
        hard_fork,
        storage::Storage
    },
    p2p::{
        error::P2pError,
        packet::{
            ChainRequest,
            ObjectRequest,
            Packet,
            PacketWrapper
        }
    }
};

use super::{
    packet::{BlockId, ChainResponse},
    Peer,
    P2pServer
};

pub use chain_validator::*;

enum ResponseHelper {
    Requested(Block, PreVerifyBlock),
    NotRequested(Immutable<Hash>)
}

impl<S: Storage> P2pServer<S> {
    // this function basically send all our blocks based on topological order (topoheight)
    // we send up to CHAIN_SYNC_REQUEST_MAX_BLOCKS blocks id (combinaison of block hash and topoheight)
    // we add at the end the genesis block to be sure to be on the same chain as others peers
    // its used to find a common point with the peer to which we ask the chain
    pub async fn request_sync_chain_for(&self, peer: &Arc<Peer>, last_chain_sync: &mut TimestampMillis, skip_stable_height_check: bool) -> Result<(), BlockchainError> {
        trace!("Requesting chain from {}", peer);

        // This can be configured by the node operator, it will be adjusted between protocol bounds
        // and based on peer configuration
        // This will allow to boost-up syncing for those who want and can be used to use low resources for low devices
        let requested_max_size = self.max_chain_response_size;

        let packet = {
            debug!("locking storage for sync chain request");
            let storage = self.blockchain.get_storage().read().await;
            debug!("locked storage for sync chain request");
            let request = ChainRequest::new(self.build_list_of_blocks_id(&*storage).await?, requested_max_size as u16);
            trace!("Built a chain request with {} blocks", request.size());
            let ping = self.build_generic_ping_packet_with_storage(&*storage).await?;
            PacketWrapper::new(Cow::Owned(request), Cow::Owned(ping))
        };

        // Update last chain sync time
        // This will be overwritten in case
        // we got the chain response
        // This prevent us from requesting too fast the chain from peer
        *last_chain_sync = get_current_time_in_millis();

        let response = peer.request_sync_chain(packet).await?;
        debug!("Received a chain response of {} blocks", response.blocks_size());

        // Check that the peer followed our requirements
        if response.blocks_size() > requested_max_size {
            return Err(P2pError::InvalidChainResponseSize(response.blocks_size(), requested_max_size).into())
        }

        // Update last chain sync time
        *last_chain_sync = get_current_time_in_millis();

        self.handle_chain_response(peer, response, requested_max_size, skip_stable_height_check).await
    }

    // search a common point between our blockchain and the peer's one
    // when the common point is found, start sending blocks from this point
    pub async fn handle_chain_request(self: &Arc<Self>, peer: &Arc<Peer>, blocks: IndexSet<BlockId>, accepted_response_size: usize) -> Result<(), BlockchainError> {
        debug!("handle chain request for {} with {} blocks", peer, blocks.len());
        let storage = self.blockchain.get_storage().read().await;
        debug!("storage locked for chain request");
        // blocks hashes sent for syncing (topoheight ordered)
        let mut response_blocks = IndexSet::new();
        let mut top_blocks = IndexSet::new();
        // common point used to notify peer if he should rewind or not
        let common_point = self.find_common_point(&*storage, blocks).await?;
        // Lowest height of the blocks sent
        let mut lowest_common_height = None;

        if let Some(common_point) = &common_point {
            let mut topoheight = common_point.get_topoheight();
            // lets add all blocks ordered hash
            let top_topoheight = self.blockchain.get_topo_height();
            // used to detect if we find unstable height for alt tips
            let mut unstable_height = None;
            let top_height = self.blockchain.get_height();
            // check to see if we should search for alt tips (and above unstable height)
            let should_search_alt_tips = top_topoheight - topoheight < accepted_response_size as u64;
            if should_search_alt_tips {
                debug!("Peer is near to be synced, will send him alt tips blocks");
                unstable_height = Some(self.blockchain.get_stable_height() + 1);
            }

            // Search the lowest height
            let mut lowest_height = top_height;

            // complete ChainResponse blocks until we are full or that we reach the top topheight
            while response_blocks.len() < accepted_response_size && topoheight <= top_topoheight {
                trace!("looking for hash at topoheight {}", topoheight);
                let hash = storage.get_hash_at_topo_height(topoheight).await?;

                // Find the lowest height
                let height = storage.get_height_for_block_hash(&hash).await?;
                if height < lowest_height {
                    lowest_height = height;
                }

                let mut swap = false;
                if let Some(previous_hash) = response_blocks.last() {
                    let version = hard_fork::get_version_at_height(self.blockchain.get_network(), height);
                    // Due to the TX being orphaned, some TXs may be in the wrong order in V1
                    // It has been sorted in V2 and should not happen anymore
                    if version == BlockVersion::V0 && storage.has_block_position_in_order(&hash).await? && storage.has_block_position_in_order(&previous_hash).await? {
                        if self.blockchain.is_side_block_internal(&*storage, &hash, top_topoheight).await? {
                            let position = storage.get_block_position_in_order(&hash).await?;
                            let previous_position = storage.get_block_position_in_order(&previous_hash).await?;
                            // if the block is a side block, we need to check if it's in the right order
                            if position < previous_position {
                                swap = true;
                            }
                        }
                    }
                }

                if swap {
                    trace!("for chain request, swapping hash {} at topoheight {}", hash, topoheight);
                    let previous = response_blocks.pop();
                    response_blocks.insert(hash);
                    if let Some(previous) = previous {
                        response_blocks.insert(previous);
                    }
                } else {
                    trace!("for chain request, adding hash {} at topoheight {}", hash, topoheight);
                    response_blocks.insert(hash);
                }
                topoheight += 1;
            }
            lowest_common_height = Some(lowest_height);

            // now, lets check if peer is near to be synced, and send him alt tips blocks
            if let Some(mut height) = unstable_height {
                let top_height = self.blockchain.get_height();
                trace!("unstable height: {}, top height: {}", height, top_height);
                while height <= top_height && top_blocks.len() < CHAIN_SYNC_TOP_BLOCKS {
                    trace!("get blocks at height {} for top blocks", height);
                    for hash in storage.get_blocks_at_height(height).await? {
                        if !response_blocks.contains(&hash) {
                            trace!("Adding top block at height {}: {}", height, hash);
                            top_blocks.insert(hash);
                        } else {
                            trace!("Top block at height {}: {} was skipped because its already present in response blocks", height, hash);
                        }
                    }
                    height += 1;
                }
            }
        }

        debug!("Sending {} blocks & {} top blocks as response to {}", response_blocks.len(), top_blocks.len(), peer);
        peer.send_packet(Packet::ChainResponse(ChainResponse::new(common_point, lowest_common_height, response_blocks, top_blocks))).await?;
        Ok(())
    }

    // Handle the blocks from chain validator by requesting missing TXs from each header
    // We don't request the full block itself as we already have the block header
    // This may be faster, but we would use slightly more bandwidth
    // NOTE: ChainValidator must check the block hash and not trust it
    // as we are giving it the chain directly to prevent a re-compute
    async fn handle_blocks_from_chain_validator(&self, peer: &Arc<Peer>, mut chain_validator: ChainValidator<'_, S>, blocks: IndexSet<Hash>) -> Result<(), BlockchainError> {
        // now retrieve all txs from all blocks header and add block in chain

        let capacity = if self.allow_boost_sync() {
            debug!("Requesting needed blocks in boost sync mode");
            Some(PEER_OBJECTS_CONCURRENCY)
        } else {
            Some(1)
        };

        let mut scheduler = Scheduler::new(capacity);
        for hash in blocks {
            let hash = Immutable::Arc(Arc::new(hash));
            trace!("Processing block {} from chain validator", hash);
            let header = chain_validator.get_block(&hash);

            let future = async move {
                // we don't already have this block, lets retrieve its txs and add in our chain
                if !self.blockchain.has_block(&hash).await? {
                    let block = match header {
                        Some(header) => self.request_block(peer, &hash, header).await?,
                        None => {
                            self.request_blocking_object_from_peer(peer, ObjectRequest::Block(hash.clone())).await?
                                .into_block()?
                                .0
                        }
                    };

                    let pre_verify = self.blockchain.pre_verify_block(&block, Some(hash)).await?;
                    Ok::<_, BlockchainError>(ResponseHelper::Requested(block, pre_verify))
                } else {
                    Ok(ResponseHelper::NotRequested(hash))
                }
            };

            scheduler.push_back(future);
        }

        let mut blocks_executor = Executor::new();
        loop {
            select! {
                biased;
                Some(res) = blocks_executor.next() => {
                    if let Err(e) = res {
                        if !peer.is_priority() {
                            debug!("Mark {} as sync chain failed: {}", peer, e);
                            peer.set_sync_chain_failed(true);
                        }

                        return Err(e)
                    }

                    // Increase by one the limit again
                    // allow to request one new block
                    scheduler.increment_n();
                },
                Some(res) = scheduler.next() => {
                    let future = async move {
                        match res? {
                            ResponseHelper::Requested(block, pre_verify) => self.blockchain.add_new_block(block, pre_verify, BroadcastOption::Miners, false).await,
                            ResponseHelper::NotRequested(hash) => self.try_re_execution_block(hash).await,
                        }
                    };

                    // Decrease by one the limit
                    // This create a backpressure to reduce
                    // requesting too many blocks and keeping them
                    // in memory
                    scheduler.decrement_n();
                    blocks_executor.push_back(future);
                },
                else => {
                    break;
                }
            }
        }

        Ok(())
    }

    // Handle the chain validator by rewinding our current chain first
    // This should only be called with a commit point enabled
    async fn handle_chain_validator_with_rewind(&self, peer: &Arc<Peer>, pop_count: u64, chain_validator: ChainValidator<'_, S>, blocks: IndexSet<Hash>) -> Result<(Vec<(Hash, Immutable<Transaction>)>, Result<(), BlockchainError>), BlockchainError> {
        // peer chain looks correct, lets rewind our chain
        warn!("Rewinding chain because of {} (pop count: {})", peer, pop_count);
        let (topoheight, txs) = self.blockchain.rewind_chain(pop_count, false).await?;
        debug!("Rewinded chain until topoheight {}", topoheight);
        let res = self.handle_blocks_from_chain_validator(peer, chain_validator, blocks).await;

        Ok((txs, res))
    }

    // Handle a chain response from another peer
    // We receive a list of blocks hashes ordered by their topoheight
    // It also contains a CommonPoint which is a block hash point where we have the same topoheight as our peer
    // Based on the lowest height of the chain sent, we may need to rewind some blocks
    // NOTE: Only a priority node can rewind below the stable height 
    async fn handle_chain_response(&self, peer: &Arc<Peer>, mut response: ChainResponse, requested_max_size: usize, skip_stable_height_check: bool) -> Result<(), BlockchainError> {
        trace!("handle chain response from {}", peer);
        let response_size = response.blocks_size();

        let (Some(common_point), Some(lowest_height)) = (response.get_common_point(), response.get_lowest_height()) else {
            warn!("No common block was found with {}", peer);
            if response.blocks_size() > 0 {
                warn!("Peer have no common block but send us {} blocks!", response.blocks_size());
                return Err(P2pError::InvalidPacket.into())
            }
            return Ok(())
        };

        let common_topoheight = common_point.get_topoheight();
        debug!("{} found a common point with block {} at topo {} for sync, received {} blocks", peer.get_outgoing_address(), common_point.get_hash(), common_topoheight, response_size);
        let pop_count = {
            let storage = self.blockchain.get_storage().read().await;
            let expected_common_topoheight = storage.get_topo_height_for_hash(common_point.get_hash()).await?;
            if expected_common_topoheight != common_topoheight {
                error!("{} sent us a valid block hash, but at invalid topoheight (expected: {}, got: {})!", peer, expected_common_topoheight, common_topoheight);
                return Err(P2pError::InvalidCommonPoint(common_topoheight).into())
            }

            let block_height = storage.get_height_for_block_hash(common_point.get_hash()).await?;
            trace!("block height: {}, stable height: {}, topoheight: {}, hash: {}", block_height, self.blockchain.get_stable_height(), expected_common_topoheight, common_point.get_hash());
            // We are under the stable height, rewind is necessary
            let mut count = if skip_stable_height_check || peer.is_priority() || lowest_height <= self.blockchain.get_stable_height() {
                let our_topoheight = self.blockchain.get_topo_height();
                if our_topoheight > expected_common_topoheight {
                    our_topoheight - expected_common_topoheight
                } else {
                    expected_common_topoheight - our_topoheight
                }
            } else {
                0
            };

            if let Some(pruned_topo) = storage.get_pruned_topoheight().await? {
                let available_diff = self.blockchain.get_topo_height() - pruned_topo;
                if count > available_diff && !(available_diff == 0 && peer.is_priority()) {
                    warn!("Peer sent us a pop count of {} but we only have {} blocks available", count, available_diff);
                    count = available_diff;
                }
            }

            count
        };

        // Packet verification ended, handle the chain response now

        let (mut blocks, top_blocks) = response.consume();
        debug!("handling chain response from {}, {} blocks, {} top blocks, pop count {}", peer, blocks.len(), top_blocks.len(), pop_count);

        let our_previous_topoheight = self.blockchain.get_topo_height();
        let our_previous_height = self.blockchain.get_height();
        let top_len = top_blocks.len();
        let blocks_len = blocks.len();

        // merge both list together
        blocks.extend(top_blocks);

        if pop_count > 0 {
            warn!("{} sent us a pop count request of {} with {} blocks (common point: {} at {}, skip stable: {})", peer, pop_count, blocks_len, common_point.get_hash(), common_topoheight, skip_stable_height_check);
        }

        // if node asks us to pop blocks, check that the peer's height/topoheight is in advance on us
        let peer_topoheight = peer.get_topoheight();
        let our_stable_topoheight = self.blockchain.get_stable_topoheight();

        if pop_count > 0
            && peer_topoheight > our_previous_topoheight
            && peer.get_height() >= our_previous_height
            && (skip_stable_height_check || common_topoheight < our_stable_topoheight)
            // then, verify if it's a priority node, otherwise, check if we are connected to a priority node so only him can rewind us
            && (peer.is_priority() || !self.is_connected_to_a_synced_priority_node().await)
        {
            // check that if we can trust him
            if peer.is_priority() {
                warn!("Rewinding chain without checking because {} is a priority node (pop count: {})", peer, pop_count);
                // User trust him as a priority node, rewind chain without checking, allow to go below stable height also
                self.blockchain.rewind_chain(pop_count, false).await?;
            } else {
                // Verify that someone isn't trying to trick us
                // Fast check: because each block represent a topoheight, it should contains
                // at least the same blockchain size to try to replace it on our side
                if pop_count > blocks_len as u64 && blocks_len < requested_max_size {
                    // TODO: maybe we could request its whole chain for comparison until chain validator has_higher_cumulative_difficulty ?
                    // If after going through all its chain and we still have a higher cumulative difficulty, we should not rewind 
                    warn!("{} sent us a pop count of {} but only sent us {} blocks, ignoring", peer, pop_count, blocks_len);
                    return Err(P2pError::InvalidPopCount(pop_count, blocks_len as u64).into())
                }

                let capacity = if self.allow_boost_sync() {
                    debug!("Requesting needed blocks in boost sync mode");
                    Some(PEER_OBJECTS_CONCURRENCY)
                } else {
                    Some(1)
                };

                // request all blocks header and verify basic chain structure
                // Starting topoheight must be the next topoheight after common block
                // Blocks in chain response must be ordered by topoheight otherwise it will give incorrect results 
                let mut futures = Scheduler::new(capacity);
                for hash in blocks.iter().cloned() {
                    trace!("Request block header for chain validator: {}", hash);

                    let fut = async {
                        // check if we already have the block to not request it
                        if self.blockchain.has_block(&hash).await? {
                            trace!("We already have block {}, skipping", hash);
                            return Ok(None)
                        }

                        self.request_blocking_object_from_peer(peer, ObjectRequest::BlockHeader(Immutable::Owned(hash))).await?
                            .into_block_header()
                            .map(Some)
                    };

                    futures.push_back(fut);
                }

                // Retrieve the current cumulative difficulty
                let current_cumulative_difficulty = self.blockchain.get_cumulative_difficulty().await?;

                // Put it behind a Mutex to we can share it between tasks
                let chain_validator = Mutex::new(ChainValidator::new(&self.blockchain));
                {
                    let mut expected_topoheight = common_topoheight + 1;
                    // Blocks executor for sequential processing
                    let mut blocks_executor = Executor::new();
    
                    let mut exit_signal = self.exit_sender.subscribe();
                    'main: loop {
                        select! {
                            biased;
                            _ = exit_signal.recv() => {
                                debug!("Stopping chain validator due to exit signal");
                                break 'main;
                            },
                            Some(res) = blocks_executor.next() => {
                                if res? {
                                    debug!("higher cumulative difficulty found");
                                    drop(futures);
                                    break 'main;
                                }
                                // Increase by one the limit again
                                // allow to request one new block
                                futures.increment_n();
                            },
                            next = futures.next() => {
                                let Some(res) = next else {
                                    debug!("No more items in futures for chain validator");
                                    break 'main;
                                };
    
                                if let Some((block, hash)) = res? {
                                    futures.decrement_n();
                                    let chain_validator = &chain_validator;
                                    blocks_executor.push_back(async move {
                                        let mut chain_validator = chain_validator.lock().await;
                                        chain_validator.insert_block(hash, block, expected_topoheight).await?;
    
                                        chain_validator.has_higher_cumulative_difficulty(&current_cumulative_difficulty).await
                                    });
                                    
                                    expected_topoheight += 1;
                                }
                            }
                        };
                    }
                }

                let chain_validator = chain_validator.into_inner();
                // Verify that it has a higher cumulative difficulty than us
                // Otherwise we don't switch to his chain
                if !chain_validator.has_higher_cumulative_difficulty(&current_cumulative_difficulty).await? {
                    error!("{} sent us a chain response with lower cumulative difficulty than ours", peer);
                    return Err(BlockchainError::LowerCumulativeDifficulty)
                }

                // Handle the chain validator
                {
                    info!("Starting commit point for chain validator");
                    let mut storage = self.blockchain.get_storage().write().await;
                    storage.start_commit_point().await?;
                    info!("Commit point started for chain validator");
                }
                let mut res = self.handle_chain_validator_with_rewind(peer, pop_count, chain_validator, blocks).await;
                {
                    info!("Ending commit point for chain validator");
                    let apply = match res.as_ref() {
                        // In case we got a partially good chain only, and that its still better than ours
                        // we can partially switch to it if the topoheight AND the cumulative difficulty is bigger
                        Ok((_, res)) => res.is_ok() || (our_previous_topoheight < self.blockchain.get_topo_height() && current_cumulative_difficulty < self.blockchain.get_cumulative_difficulty().await?),
                        Err(_) => false,
                    };

                    {
                        debug!("locking storage write mode for commit point");
                        let mut storage = self.blockchain.get_storage().write().await;
                        debug!("locked storage write mode for commit point");

                        storage.end_commit_point(apply).await?;
                        info!("Commit point ended for chain validator, apply: {}", apply);
                    }

                    if !apply {
                        debug!("Reloading chain caches from disk due to invalidation of commit point");
                        self.blockchain.reload_from_disk().await?;

                        // Try to apply any orphaned TX back to our chain
                        // We want to prevent any loss
                        if let Ok((ref mut txs, _)) = res.as_mut() {
                            debug!("Applying back orphaned {} TXs", txs.len());
                            for (hash, tx) in txs.drain(..) {
                                debug!("Trying to apply orphaned TX {}", hash);
                                if !self.blockchain.is_tx_included(&hash).await? {
                                    debug!("TX {} is not in chain, adding it to mempool", hash);
                                    if let Err(e) = self.blockchain.add_tx_to_mempool_with_hash(tx.into_arc(), Immutable::Owned(hash), false).await {
                                        debug!("Couldn't add back to mempool after commit point rollbacked: {}", e);
                                    }
                                } else {
                                    debug!("TX {} is already in chain, skipping", hash);
                                }
                            }
                        }
                    }

                    // Return errors if any
                    res?.1?;
                }
            }
        } else {
            // no rewind are needed, process normally
            // it will first add blocks to sync, and then all alt-tips blocks if any (top blocks)
            let mut total_requested = 0;
            let start = Instant::now();

            let capacity = if self.allow_boost_sync() {
                debug!("Requesting needed blocks in boost sync mode");
                Some(PEER_OBJECTS_CONCURRENCY)
            } else {
                Some(1)
            };

            let mut futures = Scheduler::new(capacity);

            for hash in blocks {
                debug!("processing block request {}", hash);
                let fut = async {
                    let hash = Immutable::Arc(Arc::new(hash));
                    if !self.blockchain.has_block(&hash).await? {
                        debug!("Requesting boost sync block {}", hash);
                        let (block, _) = self.request_blocking_object_from_peer(peer, ObjectRequest::Block(hash.clone()))
                            .await?
                            .into_block()?;

                        let pre_verify = self.blockchain.pre_verify_block(&block, Some(hash)).await?;
                        Ok::<_, BlockchainError>(ResponseHelper::Requested(block, pre_verify))
                    } else {
                        debug!("Block {} is already in chain or being processed, verify if its in DAG", hash);
                        Ok(ResponseHelper::NotRequested(hash))
                    }
                };

                futures.push_back(fut);
            }

            // In case we must shutdown
            let mut exit_signal = self.exit_sender.subscribe();
            // Timer to update the display of our BPS (blocks per second)
            let mut internal_bps = interval(Duration::from_secs(1));
            // All blocks processed during our syncing
            let mut blocks_processed = 0;
            // Blocks executor for sequential processing
            let mut blocks_executor = Executor::new();

            'main: loop {
                select! {
                    biased;
                    _ = exit_signal.recv() => {
                        debug!("Stopping chain sync due to exit signal");
                        break 'main;
                    },
                    _ = internal_bps.tick() => {
                        self.set_chain_sync_rate_bps(blocks_processed);
                        blocks_processed = 0;
                    },
                    Some(res) = blocks_executor.next() => {
                        // If we actually requested the block
                        if res? {
                            total_requested += 1;
                        }

                        futures.increment_n();
                        blocks_processed += 1;
                    },
                    // Even with the biased select & the option future being above
                    // we must ensure we don't miss a block
                    Some(res) = futures.next() => {
                        let future = async {
                            match res? {
                                ResponseHelper::Requested(block, pre_verify) => {
                                    if let Some(hash) = pre_verify.get_block_hash() {
                                        // Block has been added already
                                        // This can occurs when the block is requested
                                        // and propagated at same time
                                        if self.blockchain.has_block(&hash).await? {
                                            return Ok(true)
                                        }
                                    }

                                    if let Err(e) = self.blockchain.add_new_block(block, pre_verify, BroadcastOption::Miners, false).await {
                                        return Err(e)
                                    }

                                    Ok(true)
                                },
                                ResponseHelper::NotRequested(hash) => {
                                    if let Err(e) = self.try_re_execution_block(hash).await {
                                        return Err(e)
                                    }

                                    Ok(false)
                                }
                            }
                        };

                        futures.decrement_n();
                        blocks_executor.push_back(future);
                    },
                    else => {
                        break 'main;
                    }
                };

                if blocks_executor.is_empty() && futures.is_empty() {
                    break;
                }
            }

            let elapsed = start.elapsed().as_secs();
            let bps = if elapsed > 0 {
                total_requested / elapsed
            } else {
                total_requested
            };
            info!("we've synced {} on {} blocks and {} top blocks in {}s ({} bps) from {}", total_requested, blocks_len, top_len, elapsed, bps, peer);

            // If we have synced a block and it was less than the max size
            // It may means we are up to date
            // Notify all peers about our new state
            if total_requested > 0 && blocks_len < requested_max_size {
                self.ping_peers().await;
            }
        }

        // If we reached this point, the sync was successful
        peer.set_sync_chain_failed(false);

        // ask inventory of this peer if we sync from too far
        // if we are not further than one sync, request the inventory
        if blocks_len > 0 && blocks_len < requested_max_size {
            let our_topoheight = self.blockchain.get_topo_height();

            stream::iter(self.peer_list.get_cloned_peers().await)
                .for_each_concurrent(None, |peer| async move {
                    let peer_topoheight = peer.get_topoheight();
                    // verify that we synced it partially well
                    if peer_topoheight >= our_topoheight && peer_topoheight - our_topoheight < STABLE_LIMIT {
                        if let Err(e) = self.request_inventory_of(&peer).await {
                            error!("Error while asking inventory to {}: {}", peer, e);
                        }
                    } else {
                        debug!("Skipping inventory request for {} because its topoheight {} is not in range of our topoheight {}", peer, peer_topoheight, our_topoheight);
                    }
                }).await;
        }

        Ok(())
    }

    // Try to re-execute the block requested if its not included in DAG order (it has no topoheight assigned)
    async fn try_re_execution_block(&self, hash: Immutable<Hash>) -> Result<(), BlockchainError> {
        trace!("check re execution block {}", hash);
        
        if self.disable_reexecute_blocks_on_sync {
            trace!("re execute blocks on sync is disabled");
            return Ok(())
        }

        {
            let storage = self.blockchain.get_storage().read().await;
            if storage.is_block_topological_ordered(&hash).await? {
                trace!("block {} is already ordered", hash);
                return Ok(())
            }
        }

        warn!("Forcing block {} re-execution", hash);
        let block = {
            let mut storage = self.blockchain.get_storage().write().await;
            debug!("storage write acquired for block forced re-execution");

            let block = storage.delete_block_with_hash(&hash).await?;
            let mut tips = storage.get_tips().await?;
            if tips.remove(&hash) {
                debug!("Block {} was a tip, removing it from tips", hash);
                storage.store_tips(&tips).await?;
            }

            let mut blocks = storage.get_blocks_at_height(block.get_height()).await?;
            if blocks.shift_remove(hash.as_ref()) {
                debug!("Block {} was at height {}, removing it from blocks at height", hash, block);
                storage.set_blocks_at_height(&blocks, block.get_height()).await?;
            }

            block
        };

        // Replicate same behavior as above branch
        self.blockchain.add_new_block(block, PreVerifyBlock::Hash(hash), BroadcastOption::Miners, false).await
    }
}