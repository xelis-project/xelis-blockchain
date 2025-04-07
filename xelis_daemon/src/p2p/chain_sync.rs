use std::{borrow::Cow, sync::Arc, time::{Duration, Instant}};

use anyhow::Context;
use futures::{stream::FuturesOrdered, StreamExt, TryStreamExt};
use indexmap::IndexSet;
use log::{debug, error, info, trace, warn};
use tokio::time::interval;
use xelis_common::{
    block::{Block, BlockVersion},
    crypto::Hash,
    immutable::Immutable,
    time::{get_current_time_in_millis, TimestampMillis},
    transaction::Transaction
};

use crate::{
    config::{CHAIN_SYNC_TOP_BLOCKS, STABLE_LIMIT},
    core::{
        error::BlockchainError,
        hard_fork,
        storage::Storage
    },
    p2p::{
        error::P2pError,
        packet::{
            chain::ChainRequest,
            object::{ObjectRequest, OwnedObjectResponse},
            Packet,
            PacketWrapper
        }
    }
};

use super::{
    chain_validator::ChainValidator,
    packet::chain::{BlockId, ChainResponse},
    peer::Peer,
    P2pServer
};

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
    async fn handle_blocks_from_chain_validator(&self, peer: &Arc<Peer>, chain_validator: ChainValidator<'_, S>) -> Result<(), BlockchainError> {
        // now retrieve all txs from all blocks header and add block in chain
        for (hash, header) in chain_validator.get_blocks() {
            trace!("Processing block {} from chain validator", hash);
            // we don't already have this block, lets retrieve its txs and add in our chain
            if !self.blockchain.has_block(&hash).await? {
                let mut futures = FuturesOrdered::new();
                for tx_hash in header.get_txs_hashes() {
                    let fut = async move {
                        // check first on disk in case it was already fetch by a previous block
                        // it can happens as TXs can be integrated in multiple blocks and executed only one time
                        // check if we find it
                        if let Ok(tx) = self.blockchain.get_tx(tx_hash).await {
                            trace!("Found the transaction {} on disk", tx_hash);
                            Ok(Immutable::Arc(tx))
                        } else { // otherwise, ask it from peer
                            let response = peer.request_blocking_object(ObjectRequest::Transaction(tx_hash.clone())).await?;
                            match response {
                                OwnedObjectResponse::Transaction(tx, _) => Ok(Immutable::Owned(tx)),
                                _ => Err(P2pError::ExpectedTransaction(response))
                            }
                        }
                    };
                    futures.push_back(fut);
                }

                let transactions = futures.try_collect().await?;
                // Assemble back the block and add it to the chain
                let block = Block::new(Immutable::Arc(header), transactions);
                self.blockchain.add_new_block(block, false, false).await?; // don't broadcast block because it's syncing
            } else {
                // We need to re execute it to make sure it's in DAG
                let mut storage = self.blockchain.get_storage().write().await;
                if !storage.is_block_topological_ordered(&hash).await {
                    match storage.delete_block_with_hash(&hash).await {
                        Ok(block) => {
                            let mut tips = storage.get_tips().await?;
                            if tips.remove(&hash) {
                                debug!("Block {} was a tip, removing it from tips", hash);
                                storage.store_tips(&tips)?;
                            }

                            warn!("Block {} is already in chain but not in DAG, re-executing it", hash);
                            self.blockchain.add_new_block_for_storage(&mut storage, block, false, false).await?;
                        },
                        Err(e) => {
                            // This shouldn't happen, but in case
                            error!("Error while deleting block {} from storage to re-execute it for chain sync: {}", hash, e);
                            continue;
                        }
                    }
                } else {
                    trace!("Block {} is already in DAG, skipping it", hash);
                }
            }
        }

        Ok(())
    }

    // Handle the chain validator by rewinding our current chain first
    // This should only be called with a commit point enabled
    async fn handle_chain_validator_with_rewind(&self, peer: &Arc<Peer>, pop_count: u64, chain_validator: ChainValidator<'_, S>) -> Result<(Vec<(Hash, Arc<Transaction>)>, Result<(), BlockchainError>), BlockchainError> {
        // peer chain looks correct, lets rewind our chain
        warn!("Rewinding chain because of {} (pop count: {})", peer, pop_count);
        let (topoheight, txs) = self.blockchain.rewind_chain(pop_count, false).await?;
        debug!("Rewinded chain until topoheight {}", topoheight);
        let res = self.handle_blocks_from_chain_validator(peer, chain_validator).await;

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
            let topoheight = storage.get_topo_height_for_hash(common_point.get_hash()).await?;
            if topoheight != common_topoheight {
                error!("{} sent us a valid block hash, but at invalid topoheight (expected: {}, got: {})!", peer, topoheight, common_topoheight);
                return Err(P2pError::InvalidCommonPoint(common_topoheight).into())
            }

            let block_height = storage.get_height_for_block_hash(common_point.get_hash()).await?;
            trace!("block height: {}, stable height: {}, topoheight: {}, hash: {}", block_height, self.blockchain.get_stable_height(), topoheight, common_point.get_hash());
            // We are under the stable height, rewind is necessary
            let mut count = if skip_stable_height_check || peer.is_priority() || lowest_height <= self.blockchain.get_stable_height() {
                let our_topoheight = self.blockchain.get_topo_height();
                if our_topoheight > topoheight {
                    our_topoheight - topoheight
                } else {
                    topoheight - our_topoheight
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
            warn!("{} sent us a pop count request of {} with {} blocks", peer, pop_count, blocks_len);
        }

        // if node asks us to pop blocks, check that the peer's height/topoheight is in advance on us
        let peer_topoheight = peer.get_topoheight();
        if pop_count > 0
            && peer_topoheight > our_previous_topoheight
            && peer.get_height() >= our_previous_height
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
                if pop_count > blocks_len as u64 {
                    // TODO: maybe we could request its whole chain for comparison until chain validator has_higher_cumulative_difficulty ?
                    // If after going through all its chain and we still have a higher cumulative difficulty, we should not rewind 
                    warn!("{} sent us a pop count of {} but only sent us {} blocks, ignoring", peer, pop_count, blocks_len);
                    return Err(P2pError::InvalidPopCount(pop_count, blocks_len as u64).into())
                }

                // request all blocks header and verify basic chain structure
                // Starting topoheight must be the next topoheight after common block
                // Blocks in chain response must be ordered by topoheight otherwise it will give incorrect results 
                let mut futures = FuturesOrdered::new();
                for hash in blocks {
                    trace!("Request block header for chain validator: {}", hash);

                    let fut = async {
                        // check if we already have the block to not request it
                        if self.blockchain.has_block(&hash).await? {
                            trace!("We already have block {}, skipping", hash);
                            return Ok(None)
                        }
    
                        let response = peer.request_blocking_object(ObjectRequest::BlockHeader(hash)).await?;
                        match response {
                            OwnedObjectResponse::BlockHeader(header, hash) => Ok(Some((header, hash))),
                            _ => Err(P2pError::ExpectedBlock(response))
                        }
                    };

                    futures.push_back(fut);
                }

                let mut chain_validator = ChainValidator::new(&self.blockchain, common_topoheight + 1);
                let mut exit_signal = self.exit_sender.subscribe();
                'main: loop {
                    tokio::select! {
                        _ = exit_signal.recv() => {
                            debug!("Stopping chain validator due to exit signal");
                            break 'main;
                        },
                        next = futures.next() => {
                            let Some(res) = next else {
                                debug!("No more items in futures for chain validator");
                                break 'main;
                            };

                            if let Some((block, hash)) = res? {
                                chain_validator.insert_block(hash, block).await?;
                            }
                        }
                    };
                }

                // Verify that it has a higher cumulative difficulty than us
                // Otherwise we don't switch to his chain
                if !chain_validator.has_higher_cumulative_difficulty().await? {
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
                let mut res = self.handle_chain_validator_with_rewind(peer, pop_count, chain_validator).await;
                {
                    info!("Ending commit point for chain validator");
                    let apply = res.as_ref()
                        .map(|(_, v)| v.is_ok())
                        .unwrap_or(false);

                    let mut storage = self.blockchain.get_storage().write().await;
                    storage.end_commit_point(apply).await?;
                    info!("Commit point ended for chain validator, apply: {}", apply);

                    if !apply {
                        debug!("Reloading chain caches from disk due to invalidation of commit point");
                        self.blockchain.reload_from_disk_with_storage(&mut *storage).await?;

                        // Try to apply any orphaned TX back to our chain
                        // We want to prevent any loss
                        if let Ok((ref mut txs, _)) = res.as_mut() {
                            debug!("Applying back orphaned {} TXs", txs.len());
                            for (hash, tx) in txs.drain(..) {
                                debug!("Trying to apply orphaned TX {}", hash);
                                if !storage.has_transaction(&hash).await? && {
                                    let mempool = self.blockchain.get_mempool().read().await;
                                    !mempool.contains_tx(&hash)
                                } {
                                    debug!("TX {} is not in chain, adding it to mempool", hash);
                                    if let Err(e) = self.blockchain.add_tx_to_mempool_with_storage_and_hash(&storage, tx, Immutable::Owned(hash), false).await {
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
            if self.allow_boost_sync() {
                debug!("Requesting needed blocks in boost sync mode");
                let mut futures = FuturesOrdered::new();
                let group_id = self.object_tracker.next_group_id();

                {
                    // Lock one time only
                    let storage = self.blockchain.get_storage().read().await;
                    for hash in blocks {
                        debug!("processing block request {}", hash);
                        let request_block = storage.has_block_with_hash(&hash).await?;
                        debug!("request block: {}", hash);
                        let fut = async move {
                            if !request_block {
                                debug!("Requesting boost sync block {}", hash);
                                let mut receiver = self.object_tracker.request_object_from_peer_with_or_get_notified(Arc::clone(peer), ObjectRequest::Block(hash.clone()), Some(group_id)).await?;
                                debug!("Waiting boost sync block response {}", hash);
                                let response = receiver.recv().await
                                    .context("Error while receiving response for block while syncing")?;
    
                                match response {
                                    OwnedObjectResponse::Block(block, _) => Ok(Some(block)),
                                    _ => Err(P2pError::ExpectedBlock(response))
                                }
                            } else {
                                debug!("Block {} is already in chain, verify if its in DAG", hash);
                                let mut storage = self.blockchain.get_storage().write().await;
                                debug!("storage write lock acquired for potential block {} deletion", hash);
                                let block = if !storage.is_block_topological_ordered(&hash).await {
                                    match storage.delete_block_with_hash(&hash).await {
                                        Ok(block) => {
                                            let mut tips = storage.get_tips().await?;
                                            if tips.remove(&hash) {
                                                debug!("Block {} was a tip, removing it from tips", hash);
                                                storage.store_tips(&tips)?;
                                            }

                                            Some(block)
                                        },
                                        Err(e) => {
                                            // This shouldn't happen, but in case
                                            error!("Error while deleting block {} from storage to re-execute it for chain sync: {}", hash, e);
                                            None
                                        }
                                    }
                                } else {
                                    trace!("Block {} is already in DAG, skipping it", hash);
                                    None
                                };
                                debug!("storage write lock released for block {} deletion: {}", hash, block.is_some());
    
                                Ok(block)
                            }
                        };
    
                        futures.push_back(fut);
                    }
                }

                let mut exit_signal = self.exit_sender.subscribe();
                let mut internal_bps = interval(Duration::from_secs(1));
                let mut blocks_processed = 0;
                'main: loop {
                    tokio::select! {
                        _ = exit_signal.recv() => {
                            debug!("Stopping chain sync due to exit signal");
                            break 'main;
                        },
                        _ = internal_bps.tick() => {
                            self.set_chain_sync_rate_bps(blocks_processed);
                            blocks_processed = 0;
                        },
                        next = futures.next() => {
                            let Some(res) = next else {
                                debug!("No more items in futures for chain sync");
                                break 'main;
                            };

                            match res {
                                Ok(Some(block)) => {
                                    blocks_processed += 1;
                                    total_requested += 1;
                                    if let Err(e) = self.blockchain.add_new_block(block, false, false).await {
                                        // We need to drop the future before in case we have any future holding a mutex guard
                                        drop(futures);

                                        self.object_tracker.mark_group_as_fail(group_id).await;
                                        return Err(e)
                                    }
                                },
                                Ok(None) => {},
                                Err(e) => {
                                    debug!("Unregistering group id {} due to error {}", group_id, e);
                                    // Same as above
                                    drop(futures);

                                    self.object_tracker.mark_group_as_fail(group_id).await;
                                    return Err(e.into())
                                }
                            };
                        }
                    };
                }
            } else {
                debug!("Requesting needed blocks in normal mode");
                for hash in blocks {
                    if !self.blockchain.has_block(&hash).await? {
                        trace!("Block {} is not found, asking it to {} (index = {})", hash, peer.get_outgoing_address(), total_requested);
                        // Otherwise, request them one by one and wait for the response
                        let response = peer.request_blocking_object(ObjectRequest::Block(hash)).await?;
                        if let OwnedObjectResponse::Block(block, hash) = response {
                            trace!("Received block {} at height {} from {}", hash, block.get_height(), peer);
                            self.blockchain.add_new_block(block, false, false).await?;
                        } else {
                            error!("{} sent us an invalid block response", peer);
                            return Err(P2pError::ExpectedBlock(response).into())
                        }
                        total_requested += 1;
                    } else {
                        trace!("Block {} is already in chain, verify if its in DAG", hash);

                        let block = {
                            let mut storage = self.blockchain.get_storage().write().await;
                            if !storage.is_block_topological_ordered(&hash).await {
                                match storage.delete_block_with_hash(&hash).await {
                                    Ok(block) => {
                                        let mut tips = storage.get_tips().await?;
                                        if tips.remove(&hash) {
                                            debug!("Block {} was a tip, removing it from tips", hash);
                                            storage.store_tips(&tips)?;
                                        }

                                        block
                                    },
                                    Err(e) => {
                                        // This shouldn't happen, but in case
                                        error!("Error while deleting block {} from storage to re-execute it for chain sync: {}", hash, e);
                                        continue;
                                    }
                                }
                            } else {
                                trace!("Block {} is already in DAG, skipping it", hash);
                                continue;
                            }
                        };

                        warn!("Block {} is already in chain but not in DAG, re-executing it", hash);
                        self.blockchain.add_new_block(block, false, false).await?;
                    }
                }
            }

            let elapsed = start.elapsed().as_secs();
            let bps = if elapsed > 0 {
                total_requested / elapsed
            } else {
                0
            };
            info!("we've synced {} on {} blocks and {} top blocks in {}s ({} bps) from {}", total_requested, blocks_len, top_len, elapsed, bps, peer);
        }

        let peer_topoheight = peer.get_topoheight();
        // ask inventory of this peer if we sync from too far
        // if we are not further than one sync, request the inventory
        if peer_topoheight > our_previous_topoheight && blocks_len < requested_max_size {
            let our_topoheight = self.blockchain.get_topo_height();
            // verify that we synced it partially well
            if peer_topoheight >= our_topoheight && peer_topoheight - our_topoheight < STABLE_LIMIT {
                if let Err(e) = self.request_inventory_of(&peer).await {
                    error!("Error while asking inventory to {}: {}", peer, e);
                }
            }
        }

        Ok(())
    }
}