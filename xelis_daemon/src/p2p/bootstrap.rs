use std::{borrow::Cow, collections::HashSet, sync::Arc, time::Instant};

use futures::{stream, StreamExt, TryStreamExt};
use indexmap::IndexSet;
use log::{debug, error, info, trace, warn};
use xelis_common::{
    account::{VersionedBalance, VersionedNonce},
    contract::ContractMetadata,
    crypto::{Hash, PublicKey},
    immutable::Immutable,
    versioned_type::State,
    asset::VersionedAssetData,
};

use crate::{
    config::PRUNE_SAFETY_LIMIT,
    core::{
        error::BlockchainError,
        storage::{
            Storage,
            VersionedContract,
            VersionedMultiSig
        }
    },
    p2p::{
        error::P2pError,
        packet::{
            bootstrap_chain::{
                BlockMetadata,
                BootstrapChainResponse
            },
            object::{
                ObjectRequest,
                OwnedObjectResponse
            },
            Packet
        }
    }
};

use super::{packet::bootstrap_chain::{StepRequest, StepResponse, MAX_ITEMS_PER_PAGE}, peer::Peer, P2pServer};

impl<S: Storage> P2pServer<S> {
// Handle a bootstrap chain request
    // We have differents steps available for a bootstrap sync
    // We verify that they are send in good order
    pub(super) async fn handle_bootstrap_chain_request(self: &Arc<Self>, peer: &Arc<Peer>, request: StepRequest<'_>) -> Result<(), BlockchainError> {
        let request_kind = request.kind();
        debug!("Handle bootstrap chain request {:?} from {}", request_kind, peer);

        let storage = self.blockchain.get_storage().read().await;
        let pruned_topoheight = storage.get_pruned_topoheight().await?.unwrap_or(0);
        if let Some(topoheight) = request.get_requested_topoheight() {
            let our_topoheight = self.blockchain.get_topo_height();
            if
                pruned_topoheight >= topoheight
                || topoheight > our_topoheight
            {
                warn!("Invalid begin topoheight (received {}, our is {}, pruned: {}) received from {} on step {:?}", topoheight, our_topoheight, pruned_topoheight, peer, request_kind);
                return Err(P2pError::InvalidRequestedTopoheight.into())
            }

            // Check that the block is in stable topoheight
            if topoheight > self.blockchain.get_stable_topoheight() {
                warn!("Requested topoheight {} is not stable ({}), ignoring {:?}", topoheight, self.blockchain.get_stable_topoheight(), request_kind);
                return Err(P2pError::InvalidRequestedTopoheight.into())
            }
        }

        let response = match request {
            StepRequest::ChainInfo(blocks) => {
                let common_point = self.find_common_point(&*storage, blocks).await?;
                let tips = storage.get_tips().await?;
                let (hash, height) = self.blockchain.find_common_base::<S, _>(&storage, &tips).await?;
                let stable_topo = storage.get_topo_height_for_hash(&hash).await?;
                StepResponse::ChainInfo(common_point, stable_topo, height, hash)
            },
            StepRequest::Assets(min, max, page) => {
                if min > max {
                    warn!("Invalid range for assets");
                    return Err(P2pError::InvalidPacket.into())
                }

                let page = page.unwrap_or(0);
                let assets = storage.get_partial_assets(MAX_ITEMS_PER_PAGE, page as usize * MAX_ITEMS_PER_PAGE, min, max).await?;
                let page = if assets.len() == MAX_ITEMS_PER_PAGE {
                    Some(page + 1)
                } else {
                    None
                };
                StepResponse::Assets(assets, page)
            },
            StepRequest::Balances(keys, asset, min, max) => {
                if min > max {
                    warn!("Invalid range for account balance");
                    return Err(P2pError::InvalidPacket.into())
                }

                // move references only
                let asset = &asset;
                let storage = &storage;

                let balances: Vec<Option<_>> = stream::iter(keys.into_owned())
                    .map(|key| async move {
                            storage.get_account_summary_for(&key, asset, min, max).await
                        }
                    )
                    .buffered(self.stream_concurrency)
                    .try_collect()
                    .await?;

                trace!("Sending {} balances to {}", balances.len(), peer);
                StepResponse::Balances(balances)
            },
            StepRequest::SpendableBalances(key, asset, min, max) => {
                if min > max {
                    warn!("Invalid range for spendable balances");
                    return Err(P2pError::InvalidPacket.into())
                }

                if max > self.blockchain.get_stable_topoheight() {
                    warn!("Requested spendable balances for topoheight {} but our stable topoheight is {}", max, self.blockchain.get_stable_topoheight());
                    return Err(P2pError::InvalidRequestedTopoheight.into())
                }

                let (balances, next_max) = storage.get_spendable_balances_for(&key, &asset, min, max).await?;
                StepResponse::SpendableBalances(balances, next_max)
            },
            StepRequest::Nonces(min, max, keys) => {
                if min > max {
                    warn!("Invalid range for nonces");
                    return Err(P2pError::InvalidPacket.into())
                }

                // move references only
                let storage = &storage;

                let nonces: Vec<State<u64>> = stream::iter(keys.into_owned())
                    .map(|key| async move {
                        storage.get_nonce_at_maximum_topoheight(&key, max).await
                            .map(|v| v.map(|(topo, v)| {
                                if topo < min {
                                    State::Clean
                                } else {
                                    State::Some(v.get_nonce())
                                }
                            }).unwrap_or(State::None))
                    })
                    .buffered(self.stream_concurrency)
                    .try_collect()
                    .await?;

                StepResponse::Nonces(nonces)
            },
            StepRequest::Keys(min, max, page) => {
                if min > max {
                    warn!("Invalid range for keys");
                    return Err(P2pError::InvalidPacket.into())
                }

                let page = page.unwrap_or(0);
                let (keys, _) = storage.get_registered_keys(MAX_ITEMS_PER_PAGE, page as usize * MAX_ITEMS_PER_PAGE, min, max).await?;
                let page = if keys.len() == MAX_ITEMS_PER_PAGE {
                    Some(page + 1)
                } else {
                    None
                };
                StepResponse::Keys(keys, page)
            },
            StepRequest::MultiSigs(min, max, keys) => {
                let multisigs = storage.get_updated_multisigs(&keys, min, max).await?;
                StepResponse::MultiSigs(multisigs)
            },
            StepRequest::Contracts(min, max, page) => {
                if min > max {
                    warn!("Invalid range for contracts");
                    return Err(P2pError::InvalidPacket.into())
                }

                let page = page.unwrap_or(0);
                let contracts = storage.get_contracts(MAX_ITEMS_PER_PAGE, page as usize * MAX_ITEMS_PER_PAGE, min, max).await?;
                let page = if contracts.len() == MAX_ITEMS_PER_PAGE {
                    Some(page + 1)
                } else {
                    None
                };
                StepResponse::Contracts(contracts, page)
            },
            StepRequest::ContractMetadata(min, max, contract) => {
                if min > max {
                    warn!("Invalid range for contract metadata");
                    return Err(P2pError::InvalidPacket.into())
                }

                let contract = storage.get_contract_at_maximum_topoheight_for(&contract, max).await?;
                let state = match contract {
                    Some((topo, v)) => {
                        if topo < min {
                            State::Clean
                        } else {
                            match v.take() {
                                Some(v) => State::Some(ContractMetadata { module: v.into_owned() }),
                                None => State::Deleted,
                            }
                        }
                    },
                    None => State::None,
                };

                StepResponse::ContractMetadata(state)
            },
            StepRequest::BlocksMetadata(topoheight) => {
                // go from the lowest available point until the requested stable topoheight
                let lower = if topoheight - PRUNE_SAFETY_LIMIT <= pruned_topoheight {
                    pruned_topoheight + 1
                } else {
                    topoheight - PRUNE_SAFETY_LIMIT
                };

                let storage = &storage;
                let blocks: IndexSet<BlockMetadata> = stream::iter(lower..=topoheight)
                    .map(|topoheight| async move {
                        let hash = storage.get_hash_at_topo_height(topoheight).await?;
                        let supply = storage.get_supply_at_topo_height(topoheight).await?;
                        let burned_supply = storage.get_burned_supply_at_topo_height(topoheight).await?;
                        let reward = storage.get_block_reward_at_topo_height(topoheight)?;
                        let difficulty = storage.get_difficulty_for_block_hash(&hash).await?;
                        let cumulative_difficulty = storage.get_cumulative_difficulty_for_block_hash(&hash).await?;
                        let p = storage.get_estimated_covariance_for_block_hash(&hash).await?;

                        Ok::<_, BlockchainError>(BlockMetadata { hash, supply, burned_supply, reward, difficulty, cumulative_difficulty, p })
                    })
                    .buffered(self.stream_concurrency)
                    .try_collect()
                    .await?;

                StepResponse::BlocksMetadata(blocks)
            },
        };
        peer.send_packet(Packet::BootstrapChainResponse(BootstrapChainResponse::new(response))).await?;
        Ok(())
    }

    // first, retrieve chain info of selected peer
    // We retrieve all assets through pagination,
    // then we fetch all keys with its nonces and its balances (also through pagination)
    // and for the last step, retrieve last STABLE TOPOHEIGHT - PRUNE_SAFETY_LIMIT blocks
    // reload blockchain cache from disk, and we're ready to sync the rest of the chain
    // NOTE: it could be even faster without retrieving each TXs, but we do it in case user don't enable pruning
    pub(super) async fn bootstrap_chain(&self, peer: &Arc<Peer>) -> Result<(), BlockchainError> {
        let start = Instant::now();
        info!("Starting fast sync with {}", peer);

        let mut our_topoheight = self.blockchain.get_topo_height();

        let mut stable_topoheight = 0;
        let mut step: Option<StepRequest> = {
            let storage = self.blockchain.get_storage().read().await;
            Some(StepRequest::ChainInfo(self.build_list_of_blocks_id(&*storage).await?))
        };

        // keep them in memory, we add them when we're syncing
        // it's done to prevent any sync failure
        let mut top_topoheight: u64 = 0;
        let mut top_height: u64 = 0;
        let mut top_block_hash: Option<Hash> = None;

        loop {
            let response = if let Some(step) = step.take() {
                info!("Requesting step {:?}", step.kind());
                // This will also verify that the received step is the requested one
                peer.request_boostrap_chain(step).await?
            } else {
                break;
            };

            step = match response {
                StepResponse::ChainInfo(common_point, topoheight, height, hash) => {
                    // first, check the common point in case we deviated from the chain
                    if let Some(common_point) = common_point {
                        let mut storage = self.blockchain.get_storage().write().await;
                        debug!("Unverified common point found at {} with hash {}", common_point.get_topoheight(), common_point.get_hash());
                        let hash_at_topo = storage.get_hash_at_topo_height(common_point.get_topoheight()).await?;
                        if hash_at_topo != *common_point.get_hash() {
                            warn!("Common point is {} while our hash at topoheight {} is {}. Aborting", common_point.get_hash(), common_point.get_topoheight(), storage.get_hash_at_topo_height(common_point.get_topoheight()).await?);
                            return Err(BlockchainError::Unknown)
                        }

                        let top_block_hash = storage.get_top_block_hash().await?;
                        if *common_point.get_hash() != top_block_hash {
                            let pruned_topoheight = storage.get_pruned_topoheight().await?.unwrap_or(0);
                            
                            warn!("Common point is {} while our top block hash is {} !", common_point.get_hash(), top_block_hash);
                            // Count how much blocks we need to pop
                            let pop_count = if pruned_topoheight >= common_point.get_topoheight() {
                                our_topoheight - pruned_topoheight
                            } else {
                                our_topoheight - common_point.get_topoheight()
                            };
                            warn!("We need to pop {} blocks for fast sync", pop_count);
                            (our_topoheight, _) = self.blockchain.rewind_chain_for_storage(&mut *storage, pop_count, !peer.is_priority()).await?;
                            debug!("New topoheight after rewind is now {}", our_topoheight);
                        }
                    } else {
                        warn!("No common point with {} ! Not same chain ?", peer);
                        return Err(BlockchainError::Unknown)
                    }

                    top_topoheight = topoheight;
                    top_height = height;
                    top_block_hash = Some(hash);
                    stable_topoheight = topoheight;

                    Some(StepRequest::Assets(our_topoheight, topoheight, None))
                },
                // fetch all assets from peer
                StepResponse::Assets(assets, next_page) => {
                    {
                        let mut storage = self.blockchain.get_storage().write().await;
                        for (asset, data) in assets {
                            info!("Saving asset {} at topoheight {}", asset, stable_topoheight);
                            storage.add_asset(&asset, stable_topoheight, VersionedAssetData::new(data, None)).await?;
                        }
                    }

                    if next_page.is_some() {
                        Some(StepRequest::Assets(our_topoheight, stable_topoheight, next_page))
                    } else {
                        // We must handle all stored keys before extending our ledger
                        let mut minimum_topoheight = 0;
                        let mut i = 0;
                        let mut skip = 0;
                        loop {
                            // We request our current keys so we don't miss them
                            info!("Requesting local keys #{} at min topo {} and max topo {}", i, minimum_topoheight, our_topoheight);
                            let keys = {
                                let storage = self.blockchain.get_storage().read().await;
                                let (keys, s) = storage.get_registered_keys(MAX_ITEMS_PER_PAGE, skip, minimum_topoheight, our_topoheight).await?;

                                // Because the keys are sorted by topoheight, we can get the minimum topoheight
                                // of the last key to avoid fetching the same keys again
                                // We could use skip, but because update_bootstrap_keys can reorganize the keys,
                                // we may miss some
                                // This solution may also duplicate some keys
                                // We could do it in one request and store in memory all keys,
                                // but think about future and dozen of millions of accounts, in memory :)
                                if let Some(key) = keys.last() {
                                    debug!("Last key is {}", key.as_address(self.blockchain.get_network().is_mainnet()));
                                    minimum_topoheight = storage.get_account_registration_topoheight(key).await?;
                                    skip = s;
                                } else {
                                    break;
                                }

                                keys
                            };

                            self.update_bootstrap_keys(peer, &keys, our_topoheight, stable_topoheight).await?;
                            if keys.len() < MAX_ITEMS_PER_PAGE {
                                break;
                            }

                            i += 1;
                        }

                        // Go to next step
                        Some(StepRequest::Keys(our_topoheight, stable_topoheight, None))
                    }
                },
                // fetch all new accounts
                StepResponse::Keys(keys, next_page) => {
                    debug!("Requesting nonces for keys");
                    self.update_bootstrap_keys(peer, &keys, our_topoheight, stable_topoheight).await?;

                    if next_page.is_some() {
                        Some(StepRequest::Keys(our_topoheight, stable_topoheight, next_page))
                    } else {
                        // Go to next step
                        Some(StepRequest::Contracts(our_topoheight, stable_topoheight, None))
                    }
                },
                StepResponse::Contracts(contracts, page) => {
                    info!("Requesting contract metadata for {} contracts #{}", contracts.len(), page.unwrap_or(0));
                    stream::iter(contracts.into_iter().map(Ok::<_, BlockchainError>))
                        .try_for_each_concurrent(self.stream_concurrency, |contract| async move {
                            debug!("Requesting contract metadata for {}", contract);
                            let StepResponse::ContractMetadata(metadata) = peer.request_boostrap_chain(StepRequest::ContractMetadata(our_topoheight, stable_topoheight, Cow::Borrowed(&contract))).await? else {
                                // shouldn't happen
                                error!("Received an invalid StepResponse (how ?) while fetching contract metadata");
                                return Err(P2pError::InvalidPacket.into())
                            };

                            let mut storage = self.blockchain.get_storage().write().await;
                            match metadata {
                                // It wasn't found on their side or was deleted
                                State::None | State::Deleted => {
                                    debug!("contract metadata for {}", contract);
                                    storage.delete_last_topoheight_for_contract(&contract).await?;
                                },
                                State::Clean => {
                                    debug!("contract {} didn't changed", contract);
                                },
                                State::Some(metadata) => {
                                    debug!("Saving contract metadata for {}", contract);
                                    let module = &metadata.module;
                                    let versioned = VersionedContract::new(Some(Cow::Borrowed(module)), None);
                                    storage.set_last_contract_to(&contract, stable_topoheight, versioned).await?;
                                },
                            };

                            Ok(())
                        }).await?;

                    if page.is_some() {
                        Some(StepRequest::Contracts(our_topoheight, stable_topoheight, page))
                    } else {
                        // Go to next step
                        Some(StepRequest::BlocksMetadata(stable_topoheight))
                    }
                },
                StepResponse::BlocksMetadata(blocks) => {
                    // Last N blocks + stable block
                    if blocks.len() != PRUNE_SAFETY_LIMIT as usize + 1{
                        error!("Received {} blocks metadata while expecting {}", blocks.len(), PRUNE_SAFETY_LIMIT + 1);
                        return Err(P2pError::InvalidPacket.into())
                    }

                    let lowest_topoheight = stable_topoheight - PRUNE_SAFETY_LIMIT;

                    stream::iter(blocks.into_iter().enumerate().map(Ok))
                        .try_for_each_concurrent(self.stream_concurrency, |(i, metadata)| async move {
                            let topoheight = lowest_topoheight + i as u64;
                            trace!("Processing block metadata {} at topoheight {}", metadata.hash, topoheight);
                            // check that we don't already have this block in storage
                            if self.blockchain.has_block(&metadata.hash).await? {
                                warn!("Block {} at topo {} already in storage, skipping", metadata.hash, topoheight);
                                return Ok::<(), BlockchainError>(());
                            }

                            debug!("Saving block metadata {}", metadata.hash);
                            let OwnedObjectResponse::BlockHeader(header, hash) = peer.request_blocking_object(ObjectRequest::BlockHeader(metadata.hash)).await? else {
                                error!("Received an invalid requested object while fetching blocks metadata");
                                return Err(P2pError::InvalidPacket.into())
                            };

                            let mut txs = Vec::with_capacity(header.get_txs_hashes().len());
                            debug!("Retrieving {} txs for block {}", header.get_txs_count(), hash);
                            for tx_hash in header.get_txs_hashes() {
                                trace!("Retrieving TX {} for block {}", tx_hash, hash);
                                let tx = if self.blockchain.has_tx(tx_hash).await? {
                                    Immutable::Arc(self.blockchain.get_tx(tx_hash).await?)
                                } else {
                                    let OwnedObjectResponse::Transaction(tx, _) = peer.request_blocking_object(ObjectRequest::Transaction(tx_hash.clone())).await? else {
                                        error!("Received an invalid requested object while fetching block transaction {}", tx_hash);
                                        return Err(P2pError::InvalidObjectResponseType.into())
                                    };
                                    Immutable::Owned(tx)
                                };
                                trace!("TX {} ok", tx_hash);
                                txs.push(tx);
                            }
    
                            // link its TX to the block
                            let mut storage = self.blockchain.get_storage().write().await;
                            for tx_hash in header.get_txs_hashes() {
                                storage.add_block_for_tx(tx_hash, &hash)?;
                            }
    
                            // save metadata of this block
                            storage.set_supply_at_topo_height(topoheight, metadata.supply)?;
                            storage.set_burned_supply_at_topo_height(topoheight, metadata.burned_supply)?;
                            storage.set_block_reward_at_topo_height(topoheight, metadata.reward)?;
                            storage.set_topo_height_for_block(&hash, topoheight).await?;
    
                            storage.set_cumulative_difficulty_for_block_hash(&hash, metadata.cumulative_difficulty).await?;
    
                            // save the block with its transactions, difficulty
                            storage.save_block(Arc::new(header), &txs, metadata.difficulty, metadata.p, hash).await?;

                            Ok(())
                        }).await?;

                    info!("Cleaning data");
                    let mut storage = self.blockchain.get_storage().write().await;

                    // Delete all old data
                    storage.delete_versioned_data_below_topoheight(lowest_topoheight, true).await?;

                    storage.set_pruned_topoheight(lowest_topoheight).await?;
                    storage.set_top_topoheight(top_topoheight)?;
                    storage.set_top_height(top_height)?;
                    storage.store_tips(&HashSet::from([top_block_hash.take().ok_or(BlockchainError::Unknown)?]))?;

                    None
                },
                response => { // shouldn't happens
                    error!("Received bootstrap chain response {:?} but didn't asked for it", response);
                    return Err(P2pError::InvalidPacket.into());
                }
            };
        }

        info!("Reload caches from disk");
        self.blockchain.reload_from_disk().await?;
        info!("Fast sync done with {}, took {}", peer, humantime::format_duration(start.elapsed()));

        Ok(())
    }

    // Handle the key nonces
    async fn handle_nonces(&self, peer: &Arc<Peer>, keys: &IndexSet<PublicKey>, our_topoheight: u64, stable_topoheight: u64) -> Result<(), P2pError> {
        let StepResponse::Nonces(nonces) = peer.request_boostrap_chain(StepRequest::Nonces(our_topoheight, stable_topoheight, Cow::Borrowed(&keys))).await? else {
            // shouldn't happen
            error!("Received an invalid StepResponse (how ?) while fetching nonces");
            return Err(P2pError::InvalidPacket.into())
        };

        let mut storage = self.blockchain.get_storage().write().await;
        // save all nonces
        for (key, nonce) in keys.iter().zip(nonces) {
            match nonce {
                State::Clean => {
                    trace!("No nonce change for {}", key.as_address(self.blockchain.get_network().is_mainnet()));
                },
                State::Deleted | State::None => {
                    trace!("Deleting nonce for {}", key.as_address(self.blockchain.get_network().is_mainnet()));
                    storage.delete_last_topoheight_for_nonce(key).await?;
                    storage.delete_account_registration(key).await?;
                },
                State::Some(nonce) => {
                    trace!("Saving nonce for {}", key.as_address(self.blockchain.get_network().is_mainnet()));
                    storage.set_last_nonce_to(key, stable_topoheight, &VersionedNonce::new(nonce, None)).await?;
                    storage.set_account_registration_topoheight(key, stable_topoheight).await?;
                },
            };
        }


        Ok(())
    }

    async fn handle_multisigs(&self, peer: &Arc<Peer>, keys: &IndexSet<PublicKey>, our_topoheight: u64, stable_topoheight: u64) -> Result<(), P2pError> {
        // Also request the multisigs states
        let StepResponse::MultiSigs(multisigs) = peer.request_boostrap_chain(StepRequest::MultiSigs(our_topoheight, stable_topoheight, Cow::Borrowed(keys))).await? else {
            // shouldn't happen
            error!("Received an invalid StepResponse (how ?) while fetching multisigs");
            return Err(P2pError::InvalidPacket.into())
        };

        let mut storage = self.blockchain.get_storage().write().await;
        // save all multisigs
        for (key, multisig) in keys.iter().zip(multisigs) {
            match multisig {
                State::None | State::Clean => {
                    trace!("No multisig change for {}", key.as_address(self.blockchain.get_network().is_mainnet()));
                },
                State::Deleted => {
                    trace!("Deleting multisig for {}", key.as_address(self.blockchain.get_network().is_mainnet()));
                    storage.delete_last_topoheight_for_multisig(key).await?;
                },
                State::Some(multisig) => {
                    trace!("Saving multisig for {}", key.as_address(self.blockchain.get_network().is_mainnet()));
                    let data = VersionedMultiSig::new(Some(Cow::Owned(multisig)), None);
                    storage.set_last_multisig_to(key, stable_topoheight, data).await?;
                },
            };
        }


        Ok(())
    }

    async fn handle_balances_for_asset(&self, peer: &Arc<Peer>, asset: &Hash, keys: &IndexSet<PublicKey>, our_topoheight: u64, stable_topoheight: u64) -> Result<(), P2pError> {
        debug!("Requesting balances for asset {} at topo {}", asset, stable_topoheight);
        let StepResponse::Balances(balances) = peer.request_boostrap_chain(StepRequest::Balances(Cow::Borrowed(&keys), Cow::Borrowed(asset), our_topoheight, stable_topoheight)).await? else {
            // shouldn't happen
            error!("Received an invalid StepResponse (how ?) while fetching balances");
            return Err(P2pError::InvalidPacket.into())
        };

        // save all balances for this asset
        let blockchain = &self.blockchain;
        stream::iter(keys.iter().zip(balances).map(Ok))
            .try_for_each_concurrent(self.stream_concurrency, |(key, balance)| async move {
                // check that the account have balance for this asset
                if let Some(account) = balance {
                    info!("Fetching balance history for {}", key.as_address(blockchain.get_network().is_mainnet()));

                    // Each version are applied on iteration N+1 of the loop
                    // This is done to get the previous topoheight of the current version
                    let mut previous_version: Option<(u64, VersionedBalance)> = None;
                    // Highest topoheight bound for balance history
                    let mut max_topoheight = Some(account.stable_topoheight);
                    // Lowest topoheight bound for balance histor
                    let min_topo = account.output_topoheight.unwrap_or(0);

                    let mut highest_topoheight = None;
                    // Go through all balance history
                    while let Some(max) = max_topoheight {
                        debug!("Requesting spendable balances for asset {} at max topo {} for {}", asset, max, key.as_address(blockchain.get_network().is_mainnet()));
                        let StepResponse::SpendableBalances(balances, max_next) = peer.request_boostrap_chain(StepRequest::SpendableBalances(Cow::Borrowed(&key), Cow::Borrowed(&asset), min_topo, max)).await? else {
                            // shouldn't happen
                            error!("Received an invalid StepResponse (how ?) while fetching balances");
                            return Err(P2pError::InvalidPacket)
                        };

                        for balance in balances {
                            let (topo, version) = balance.as_version();
                            if highest_topoheight.is_none() {
                                highest_topoheight = Some(topo);
                            }

                            if let Some((prev_topo, mut prev)) = previous_version {
                                prev.set_previous_topoheight(Some(topo));

                                let mut storage = blockchain.get_storage().write().await;
                                storage.set_balance_at_topoheight(&asset, prev_topo, &key, &prev).await?;
                            }

                            previous_version = Some((topo, version));
                        }

                        max_topoheight = max_next;
                    }

                    // Store the oldest balance version
                    if let Some((topo, prev)) = previous_version {
                        let mut storage = blockchain.get_storage().write().await;
                        storage.set_balance_at_topoheight(&asset, topo, &key, &prev).await?;
                    }

                    // Store the highest topoheight as the last topoheight for this asset balance
                    if let Some(highest_topoheight) = highest_topoheight {
                        let mut storage = blockchain.get_storage().write().await;
                        storage.set_last_topoheight_for_balance(&key, &asset, highest_topoheight)?;
                    }
                } else {
                    debug!("No balance for key {} at topoheight {}", key.as_address(blockchain.get_network().is_mainnet()), stable_topoheight);
                }

                Ok(())
            }).await?;

        Ok(())
    }

    // Update all keys using bootstrap request
    // This will fetch the nonce and associated balance for each asset
    async fn update_bootstrap_keys(&self, peer: &Arc<Peer>, keys: &IndexSet<PublicKey>, our_topoheight: u64, stable_topoheight: u64) -> Result<(), P2pError> {
        if keys.is_empty() {
            warn!("No keys to update");
            return Ok(())
        }

        self.handle_nonces(peer, keys, our_topoheight, stable_topoheight).await?;
        self.handle_multisigs(peer, keys, our_topoheight, stable_topoheight).await?;

        let mut page = 0;
        loop {
            // Retrieve chunked assets
            let assets = {
                let storage = self.blockchain.get_storage().read().await;
                let assets = storage.get_chunked_assets(MAX_ITEMS_PER_PAGE, page * MAX_ITEMS_PER_PAGE).await?;
                if assets.is_empty() {
                    break;
                }
                page += 1;
                assets
            };

            // Request every asset balances
            for asset in assets {
                self.handle_balances_for_asset(peer, &asset, keys, our_topoheight, stable_topoheight).await?;
            }
        }

        Ok(())
    }
}