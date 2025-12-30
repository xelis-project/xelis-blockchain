mod bootstrap;
mod chain_validator;

use std::{
    borrow::Cow,
    sync::Arc,
    time::{Duration, Instant}
};
use anyhow::Context;
use futures::{
    stream,
    StreamExt,
};
use indexmap::IndexSet;
use log::{debug, error, info, trace, warn};
use metrics::histogram;
use xelis_common::{
    block::{Block, BlockVersion},
    crypto::Hash,
    difficulty::CumulativeDifficulty,
    immutable::Immutable,
    time::{get_current_time_in_millis, TimestampMillis},
    tokio::{
        select,
        time::{interval, sleep},
        sync::Mutex,
        Executor,
        Scheduler
    },
    transaction::Transaction
};

use crate::{
    config::{CHAIN_SYNC_DELAY, CHAIN_SYNC_TOP_BLOCKS, MILLIS_PER_SECOND, PEER_OBJECTS_CONCURRENCY, STABLE_LIMIT},
    core::{
        hard_fork,
        blockchain::{BroadcastOption, PreVerifyBlock},
        error::BlockchainError,
        storage::{
            Storage,
            snapshot::{SnapshotWrapper, StorageHolder},
        },
        blockdag,
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
            trace!("Built a chain request with {} blocks", request.len());
            let ping = self.build_generic_ping_packet_with_storage(&*storage).await?;
            PacketWrapper::new(Cow::Owned(request), Cow::Owned(ping))
        };

        // Update last chain sync time
        // This will be overwritten in case
        // we got the chain response
        // This prevent us from requesting too fast the chain from peer
        *last_chain_sync = get_current_time_in_millis();

        let response = peer.request_sync_chain(packet).await;

        // Set the last chain sync time in seconds for the peer
        peer.set_last_chain_sync_out(get_current_time_in_millis());

        let response = response?;
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
        let start = Instant::now();

        // blocks hashes sent for syncing (topoheight ordered)
        let mut response_blocks = IndexSet::new();
        let mut top_blocks = IndexSet::new();
        // common point used to notify peer if he should rewind or not
        // Lowest height of the blocks sent
        let mut lowest_common_height = None;
        
        let common_point = {
            let storage = self.blockchain.get_storage().read().await;
            let common_point = self.find_common_point(&*storage, blocks).await?;
            debug!("storage locked for chain request");

            if let Some(common_point) = &common_point {
                let mut topoheight = common_point.get_topoheight();
                // lets add all blocks ordered hash
                let chain_cache = storage.chain_cache().await;
                let top_topoheight = chain_cache.topoheight;
                // used to detect if we find unstable height for alt tips
                let mut unstable_height = None;
                let top_height = chain_cache.height;
                // check to see if we should search for alt tips (and above unstable height)
                let should_search_alt_tips = top_topoheight - topoheight < accepted_response_size as u64;
                if should_search_alt_tips {
                    debug!("Peer is near to be synced, will send him alt tips blocks");
                    unstable_height = Some(chain_cache.stable_height + 1);
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
                        if (version == BlockVersion::V0 || version >= BlockVersion::V3) && storage.has_block_position_in_order(&hash).await? && storage.has_block_position_in_order(&previous_hash).await? {
                            let position = storage.get_block_position_in_order(&hash).await?;
                            let previous_position = storage.get_block_position_in_order(&previous_hash).await?;
                            // if the block is a side block, we need to check if it's in the right order
                            if position < previous_position {
                                if blockdag::is_side_block_internal(&*storage, &hash, Some(topoheight), top_topoheight, version).await? {
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
                    trace!("unstable height: {}, top height: {}", height, top_height);
                    while height <= top_height && top_blocks.len() < CHAIN_SYNC_TOP_BLOCKS {
                        trace!("get blocks at height {} for top blocks", height);
                        for hash in storage.get_blocks_at_height(height).await? {
                            if !response_blocks.contains(&hash) {
                                trace!("Adding top block at height {}: {}", height, hash);
                                if !top_blocks.insert(hash) {
                                    debug!("Top block was already present in response top blocks");
                                }
                            } else {
                                trace!("Top block at height {}: {} was skipped because its already present in response blocks", height, hash);
                            }
                        }
                        height += 1;
                    }
                }

                // Too many top blocks, use the one with highest difficulty
                if top_blocks.len() >= u8::MAX as usize {
                    debug!("Too many top blocks ({}), sorting and keeping only the best ones", top_blocks.len());
                    // sort and keep only the best ones
                    let iter = blockdag::sort_tips(&*storage, top_blocks.into_iter()).await?;
                    top_blocks = iter.take(u8::MAX as usize).collect();
                }
            }

            common_point
        };

        let elapsed = start.elapsed();
        histogram!("xelis_p2p_chain_request_s").record(elapsed.as_secs_f64());

        debug!("Sending {} blocks & {} top blocks as response to {} in {:?}", response_blocks.len(), top_blocks.len(), peer, elapsed);
        peer.send_packet(Packet::ChainResponse(ChainResponse::new(common_point, lowest_common_height, response_blocks, top_blocks))).await?;
        Ok(())
    }

    // Iteratively request the peer's chain in chunks and validate it
    // This method will request blocks starting from a common point until we have enough blocks to validate the pop_count
    // or until we find that the peer has a higher cumulative difficulty
    async fn validate_peer_chain(
        &self,
        peer: &Arc<Peer>,
        common_topoheight: u64,
        pop_count: u64,
        current_cumulative_difficulty: &CumulativeDifficulty,
        initial_blocks: IndexSet<Hash>,
        requested_max_size: usize,
    ) -> Result<ChainValidator<'_, S>, BlockchainError> {
        let chain_validator = Mutex::new(ChainValidator::new(&self.blockchain));
        let mut all_blocks = initial_blocks;
        let mut expected_topoheight = common_topoheight + 1;
        let mut total_validated = 0u64;
        let mut processed = IndexSet::new();

        let capacity = if self.allow_boost_sync() {
            debug!("Requesting needed blocks in boost sync mode");
            Some(PEER_OBJECTS_CONCURRENCY)
        } else {
            Some(1)
        };

        // Continue requesting chunks until we have enough blocks to validate pop_count
        // or until we find higher cumulative difficulty
        while total_validated < pop_count {
            debug!("Validating chunk at topoheight {}, total validated: {}/{}", expected_topoheight, total_validated, pop_count);
            let Some(last_block) = all_blocks.last().cloned() else {
                debug!("No more blocks to validate from peer {}", peer);
                break;
            };

            // Request blocks from the peer in chunks
            let mut futures = Scheduler::new(capacity);
            for hash in all_blocks.drain(..) {
                let hash= Arc::new(hash);
                if !processed.insert(hash.clone()) {
                    warn!("Block {} was already processed for chain validation, skipping", hash);
                    continue;
                }

                trace!("Request block {} for chain validator", hash);

                let fut = async {
                    // check if we already have the block to not request it
                    if self.blockchain.has_block(&hash).await? {
                        trace!("We already have block {}, skipping", hash);
                        return Ok((None, hash))
                    }

                    self.request_blocking_object_from_peer(peer, ObjectRequest::BlockHeader(Immutable::Arc(hash.clone()))).await?
                        .into_block_header()
                        .map(|(block, _)| (Some(block), hash))
                };

                futures.push_back(fut);
            }

            // Process the chunk
            let mut blocks_executor = Executor::new();
            let mut exit_signal = self.exit_sender.subscribe();
            let mut validated_in_chunk = 0u64;
            let mut found_higher_difficulty = false;

            'chunk: loop {
                select! {
                    biased;
                    _ = exit_signal.recv() => {
                        debug!("Stopping chain validator due to exit signal");
                        return Err(P2pError::Disconnected.into());
                    },
                    Some(res) = blocks_executor.next() => {
                        if res? {
                            debug!("Higher cumulative difficulty found during validation");
                            found_higher_difficulty = true;
                            drop(futures);
                            break 'chunk;
                        }
                        futures.increment_n();
                    },
                    next = futures.next() => {
                        let Some(res) = next else {
                            debug!("No more items in futures for chunk validator");
                            break 'chunk;
                        };

                        let (block, hash) = res?;
                        futures.decrement_n();
                        let chain_validator = &chain_validator;
                        blocks_executor.push_back(async move {
                            let mut chain_validator = chain_validator.lock().await;
                            chain_validator.insert_block(hash, block, expected_topoheight).await?;
                            chain_validator.has_higher_cumulative_difficulty(current_cumulative_difficulty).await
                        });
                        
                        expected_topoheight += 1;
                        validated_in_chunk += 1;
                    }
                };
            }

            total_validated += validated_in_chunk;

            // If we found higher difficulty or validated enough, stop
            if found_higher_difficulty || total_validated >= pop_count {
                debug!("Stopping validation from peer {} (higher difficulty: {}, total validated: {}/{})", peer, found_higher_difficulty, total_validated, pop_count);
                break;
            }

            // If we processed all available blocks but still need more, request another chunk
            if total_validated < pop_count {
                info!("Requesting more blocks from peer for validation using last block {}", last_block);
                // Request the next chunk from the peer
                let packet = {
                    let storage = self.blockchain.get_storage().read().await;
                    let mut blocks_id = IndexSet::new();
                    // Start from where we left off
                    blocks_id.insert(BlockId::new(last_block, expected_topoheight - 1));

                    let genesis_block = storage.get_hash_at_topo_height(0).await?;
                    blocks_id.insert(BlockId::new(genesis_block, 0));

                    let request = ChainRequest::new(blocks_id, requested_max_size as u16);
                    let ping = self.build_generic_ping_packet_with_storage(&*storage).await?;
                    PacketWrapper::new(Cow::Owned(request), Cow::Owned(ping))
                };

                let last_sync_time = peer.get_last_chain_sync_out();
                let current_time = get_current_time_in_millis();
                let tmp = last_sync_time + (CHAIN_SYNC_DELAY * MILLIS_PER_SECOND);
                if tmp > current_time {
                    let wait_duration = Duration::from_millis(tmp - current_time);
                    info!("Waiting {:?} before requesting next chain chunk from {}", wait_duration, peer);

                    sleep(wait_duration).await;
                }

                info!("Requesting additional chain chunk for validation");
                let response = peer.request_sync_chain(packet).await;
                peer.set_last_chain_sync_out(get_current_time_in_millis());
                let response = response.context("Error while waiting on next chain response")?;
                if response.blocks_size() == 0 {
                    warn!("Peer has no more blocks to send for validation");
                    break;
                }

                let (new_blocks, _) = response.consume();
                info!("Received {} new blocks for validation", new_blocks.len());
                all_blocks.extend(new_blocks);
            } else if validated_in_chunk == 0 {
                debug!("No new blocks validated in this chunk, stopping validation");
                // No progress made
                break;
            }
        }

        let chain_validator = chain_validator.into_inner();
        if !chain_validator.has_higher_cumulative_difficulty(&current_cumulative_difficulty).await? {
            error!("{} sent us a chain response with lower cumulative difficulty than ours", peer);
            return Err(BlockchainError::LowerCumulativeDifficulty)
        }

        warn!("Validated peer chain from {} with higher cumulative difficulty", peer);

        Ok(chain_validator)
    }

    // Handle the blocks from chain validator by requesting missing TXs from each header
    // We don't request the full block itself as we already have the block header
    // This may be faster, but we would use slightly more bandwidth
    // NOTE: ChainValidator must check the block hash and not trust it
    // as we are giving it the chain directly to prevent a re-compute
    async fn handle_blocks_from_chain_validator(&self, peer: &Arc<Peer>, chain_validator: ChainValidator<'_, S>, snapshot: &SnapshotWrapper<'_, S>) -> Result<(), BlockchainError> {
        // now retrieve all txs from all blocks header and add block in chain

        let capacity = if self.allow_boost_sync() {
            debug!("Requesting needed blocks in boost sync mode");
            Some(PEER_OBJECTS_CONCURRENCY)
        } else {
            Some(1)
        };

        let mut scheduler = Scheduler::new(capacity);
        for (hash, (emulated_topoheight, data)) in chain_validator.blocks().into_iter() {
            let hash = Immutable::Arc(hash);
            trace!("Processing block {} from chain validator with emulated topoheight {}", hash, emulated_topoheight);

            let future = async move {
                // we don't already have this block, lets retrieve its txs and add in our chain
                if {
                    let storage = snapshot.lock().await?;
                    !storage.has_block_with_hash(&hash).await?
                } {
                    let (block, cache) = match data {
                        Some(data) => {
                            let block = self.request_block(peer, &hash, data.header).await?;
                            let cache = PreVerifyBlock::Partial { block_hash: hash.clone(), pow_hash:  data.pow_hash };
                            (block, cache)
                        },
                        None => {
                            let block = self.request_blocking_object_from_peer(peer, ObjectRequest::Block(hash.clone())).await?
                                .into_block()?
                                .0;

                            let cache = self.blockchain.pre_verify_block(&block, Some(hash)).await?;
                            (block, cache)
                        }
                    };

                    Ok::<_, BlockchainError>(ResponseHelper::Requested(block, cache))
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
                        debug!("Mark {} as sync chain failed: {}", peer, e);
                        peer.set_sync_chain_failed(true);

                        return Err(e)
                    }

                    // Increase by one the limit again
                    // allow to request one new block
                    scheduler.increment_n();
                },
                Some(res) = scheduler.next() => {
                    let future = async move {
                        match res? {
                            ResponseHelper::Requested(block, pre_verify) => self.blockchain.add_new_block_with_storage(StorageHolder::Snapshot(snapshot), block, pre_verify, BroadcastOption::Miners, false).await,
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
    async fn handle_chain_validator_with_rewind(&self, peer: &Arc<Peer>, pop_count: u64, chain_validator: ChainValidator<'_, S>, snapshot: &SnapshotWrapper<'_, S>) -> Result<(Vec<(Hash, Immutable<Transaction>)>, Result<(), BlockchainError>), BlockchainError> {
        // peer chain looks correct, lets rewind our chain
        warn!("Rewinding chain because of {} (pop count: {})", peer, pop_count);
        let (topoheight, txs) = {
            let mut snapshot = snapshot.lock().await?;
            self.blockchain.rewind_chain_for_storage(&mut snapshot, pop_count, false).await?
        };

        debug!("Rewinded chain until topoheight {}", topoheight);
        let res = self.handle_blocks_from_chain_validator(peer, chain_validator, snapshot).await;

        if let Err(BlockchainError::ErrorOnP2p(e)) = &res {
            debug!("Mark {} as sync chain from validator failed: {}", peer, e);
            peer.set_sync_chain_failed(true);

            if let P2pError::Disconnected = e {
                // Peer disconnected while trying to reorg us, tempban it
                if let Err(e) = self.peer_list.temp_ban_address(&peer.get_connection().get_address().ip(), 60, false).await {
                    debug!("Couldn't tempban {}: {}", peer, e);
                }
            }
        }

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
                return Err(P2pError::MalformedPacket.into())
            }
            return Ok(())
        };

        let mut common_topoheight = common_point.get_topoheight();
        debug!("{} found a common point with block {} at topo {} for sync, received {} blocks", peer.get_outgoing_address(), common_point.get_hash(), common_topoheight, response_size);
        let (pop_count, our_previous_topoheight, our_previous_height, our_stable_topoheight) = {
            let storage = self.blockchain.get_storage().read().await;
            let expected_common_topoheight = storage.get_topo_height_for_hash(common_point.get_hash()).await?;

            let chain_cache = storage.chain_cache().await;
            if expected_common_topoheight != common_topoheight {
                let stable_topoheight = chain_cache.stable_topoheight;
                warn!("{} sent us a valid block hash, but at a different topoheight (expected: {}, got: {}, stable topoheight: {})!", peer, expected_common_topoheight, common_topoheight, stable_topoheight);

                if expected_common_topoheight <= stable_topoheight && !peer.is_priority() {
                    return Err(P2pError::InvalidCommonPoint(common_topoheight).into())
                }

                // Still accept it by using the expected topoheight
                // We may have some deviation with them and want to check it
                common_topoheight = expected_common_topoheight;
            }

            let block_height = storage.get_height_for_block_hash(common_point.get_hash()).await?;
            trace!("block height: {}, stable height: {}, topoheight: {}, hash: {}", block_height, chain_cache.stable_height, expected_common_topoheight, common_point.get_hash());
            // We are under the stable height, rewind is necessary
            let mut count = if skip_stable_height_check || peer.is_priority() || lowest_height <= chain_cache.stable_height {
                let our_topoheight = chain_cache.topoheight;
                if our_topoheight > expected_common_topoheight {
                    our_topoheight - expected_common_topoheight
                } else {
                    expected_common_topoheight - our_topoheight
                }
            } else {
                0
            };

            if let Some(pruned_topo) = storage.get_pruned_topoheight().await? {
                let available_diff = chain_cache.topoheight - pruned_topo;
                if count > available_diff && !(available_diff == 0 && peer.is_priority()) {
                    debug!("Peer sent us a pop count of {} but we only have {} blocks available", count, available_diff);
                    count = available_diff;
                }
            }

            (count, chain_cache.topoheight, chain_cache.height, chain_cache.stable_topoheight)
        };

        // Packet verification ended, handle the chain response now

        let (mut blocks, top_blocks) = response.consume();
        debug!("handling chain response from {}, {} blocks, {} top blocks, pop count {}", peer, blocks.len(), top_blocks.len(), pop_count);

        let top_len = top_blocks.len();
        let blocks_len = blocks.len();

        // merge both list together
        blocks.extend(top_blocks);

        if pop_count > 0 {
            warn!("{} sent us a pop count request of {} with {} blocks (common point: {} at {}, skip stable: {})", peer, pop_count, blocks_len, common_point.get_hash(), common_topoheight, skip_stable_height_check);
        }

        // if node asks us to pop blocks, check that the peer's height/topoheight is in advance on us
        let peer_topoheight = peer.get_topoheight();

        if pop_count > 0
            && peer_topoheight > our_previous_topoheight
            && peer.get_height() >= our_previous_height
            && (skip_stable_height_check || common_topoheight < our_stable_topoheight)
            // then, verify if it's a priority node, otherwise, check if we are connected to a priority node so only him can rewind us
            && (peer.is_priority() || (self.count_connected_to_a_synced_priority_node(None).await == 0))
        {
            // check that if we can trust him
            if peer.is_priority() {
                warn!("Rewinding chain without checking because {} is a priority node (pop count: {})", peer, pop_count);
                // User trust him as a priority node, rewind chain without checking, allow to go below stable height also
                self.blockchain.rewind_chain(pop_count, false).await?;
            } else if self.reorg_from_priority_only {
                warn!("Ignoring reorg request from non-priority node {} because reorg_from_priority_only is enabled", peer);
                return Err(P2pError::ReorgFromPriorityOnly.into());
            } else {
                // Verify that someone isn't trying to trick us
                // If the peer sent fewer blocks than the pop_count and didn't fill the response,
                // we need to iteratively request more blocks to validate the full chain
                warn!("{} sent us a pop count of {} with {} blocks", peer, pop_count, blocks_len);

                // Retrieve the current cumulative difficulty
                let current_cumulative_difficulty = self.blockchain.get_cumulative_difficulty().await?;

                // Iteratively request and validate the peer's chain in chunks
                let chain_validator =  self.validate_peer_chain(
                    peer,
                    common_topoheight,
                    pop_count,
                    &current_cumulative_difficulty,
                    blocks,
                    requested_max_size,
                ).await?;

                {
                    info!("Starting commit point for chain validator");
                    let storage = SnapshotWrapper::new(self.blockchain.get_storage());
                    let mut res = self.handle_chain_validator_with_rewind(peer, pop_count, chain_validator, &storage).await;

                    info!("Ending commit point for chain validator");
                    let apply = match res.as_ref() {
                        // In case we got a partially good chain only, and that its still better than ours
                        // we can partially switch to it if the topoheight AND the cumulative difficulty is bigger
                        Ok((_, res)) => {
                            if res.is_ok() {
                                true
                            } else {
                                let storage = storage.lock().await?;
                                let chain_cache = storage.chain_cache().await;
                                let topoheight = chain_cache.topoheight;

                                let cumulative_difficulty = self.blockchain.get_cumulative_difficulty_with_storage(&*storage).await?;
                                our_previous_topoheight < topoheight && current_cumulative_difficulty < cumulative_difficulty
                            }
                        },
                        Err(_) => false,
                    };

                    {
                        debug!("locking storage write mode for commit point");
                        let mut storage = storage.lock().await?;
                        debug!("locked storage write mode for commit point");

                        storage.end_snapshot(apply)?;
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

                                    if let Err(e) = self.blockchain.add_new_block(block, pre_verify, BroadcastOption::All, false).await {
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
            let our_topoheight = self.blockchain.get_topo_height().await;

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

            let block = storage.get_block_by_hash(&hash).await?;
            storage.delete_block_by_hash(&hash).await?;
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
        self.blockchain.add_new_block(block, PreVerifyBlock::Hash(hash), BroadcastOption::All, false).await
    }
}