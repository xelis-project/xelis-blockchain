use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration
};
use futures::{stream::{self, FuturesUnordered}, StreamExt, TryStreamExt};
use indexmap::IndexMap;
use thiserror::Error;
use anyhow::{Context, Error};
use log::{debug, error, info, trace, warn};
use xelis_common::{
    account::CiphertextCache,
    api::{
        daemon::{
            BlockResponse,
            MultisigState,
            NewBlockEvent,
            RPCBlockResponse,
            GetContractsOutputsResult,
            ContractTransfersEntry,
            ContractTransfersEntryKey
        },
        wallet::BalanceChanged,
    },
    config::XELIS_ASSET,
    crypto::{
        Address,
        Hash
    },
    time::{TimestampMillis, Instant},
    tokio::{
        select,
        spawn_task,
        sync::{mpsc, broadcast, Mutex, Semaphore},
        task::{JoinError, JoinHandle},
        time::sleep,
    },
    transaction::MultiSigPayload,
    utils::sanitize_ws_address
};
use crate::{
    config::AUTO_RECONNECT_INTERVAL,
    daemon_api::DaemonAPI,
    decoder,
    entry::{
        EntryData,
        TransactionEntry,
    },
    error::WalletError,
    storage::{Balance, MultiSig},
    wallet::{Event, Wallet}
};

// NetworkHandler must be behind a Arc to be accessed from Wallet (to stop it) or from tokio task
pub type SharedNetworkHandler = Arc<NetworkHandler>;

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("network handler is already running")]
    AlreadyRunning,
    #[error("network handler is not running")]
    NotRunning,
    #[error(transparent)]
    TaskError(#[from] JoinError),
    #[error(transparent)]
    DaemonAPIError(#[from] Error),
    #[error("Network mismatch")]
    NetworkMismatch
}

#[derive(Debug, Clone)]
pub enum NetworkHandlerMessage {
    Stop,
    Rescan {
        from_topoheight: u64
    },
    ScanAssets {
        assets: HashSet<Hash>
    }
}

pub struct NetworkHandler {
    // tokio task
    task: Mutex<Option<JoinHandle<Result<(), Error>>>>,
    // wallet where we can save every data from chain
    wallet: Arc<Wallet>,
    // api to communicate with daemon
    // It is behind a Arc to be shared across several wallets
    // in case someone make a custom service and don't want to create a new connection
    api: Arc<DaemonAPI>,
    // Concurrency to use during syncing
    concurrency: usize,
    // Broadcast channel to automatically subscribe to the sender of the network handler
    sender: broadcast::Sender<NetworkHandlerMessage>,
}

impl NetworkHandler {
    // Create a new network handler with a wallet and a daemon address
    // This will create itself a DaemonAPI and verify if connection is possible
    pub async fn new<S: ToString>(wallet: Arc<Wallet>, daemon_address: S, concurrency: usize) -> Result<SharedNetworkHandler, Error> {
        let s = daemon_address.to_string();
        let api = DaemonAPI::new(format!("{}/json_rpc", sanitize_ws_address(s.as_str()))).await?;
        Self::with_api(wallet, Arc::new(api), concurrency).await
    }

    // Create a new network handler with an already created daemon API
    pub async fn with_api(wallet: Arc<Wallet>, api: Arc<DaemonAPI>, concurrency: usize) -> Result<SharedNetworkHandler, Error> {
        // check that we can correctly get version from daemon
        let version = api.get_version().await?;
        debug!("Connected to daemon running version {}", version);

        let (sender, _) = broadcast::channel(16);

        Ok(Arc::new(Self {
            task: Mutex::new(None),
            wallet,
            api,
            concurrency,
            sender,
        }))
    }

    // Start the internal loop to sync all missed blocks and all newly added blocks
    pub async fn start(self: &Arc<Self>, auto_reconnect: bool) -> Result<(), NetworkError> {
        trace!("Starting network handler");

        if self.is_running().await {
            return Err(NetworkError::AlreadyRunning)
        }

        if !self.api.is_online() {
            debug!("API is offline, trying to reconnect #1");
            if !self.api.reconnect().await? {
                error!("Couldn't reconnect to server");
                return Err(NetworkError::NotRunning)
            }
        }

        let zelf = Arc::clone(&self);
        *self.task.lock().await = Some(spawn_task("network-handler", async move {
            loop {
                // Notify that we are online
                zelf.wallet.propagate_event(Event::Online).await;

                let res =  zelf.start_syncing().await;
                if let Err(e) = res.as_ref() {
                    let message = format!("{:#}", e);
                    error!("Error while syncing: {:#}", message);
                    zelf.wallet.propagate_event(Event::SyncError { message }).await;
                }

                // Notify that we are offline
                zelf.wallet.propagate_event(Event::Offline).await;

                // It was not stopped gracefully
                // We will try to reconnect if auto_reconnect is enabled, otherwise we will stop the network handler
                if !auto_reconnect || res.is_ok() {
                    // Turn off the websocket connection
                    if let Err(e) = zelf.api.disconnect().await {
                        error!("Error while closing websocket connection: {}", e);
                    }

                    break res;
                } else if res.is_err() {
                    if !zelf.api.is_online() {
                        debug!("API is offline, trying to reconnect #2");
                        if !zelf.api.reconnect().await? {
                            error!("Couldn't reconnect to server, trying again in {} seconds", AUTO_RECONNECT_INTERVAL);
                            sleep(Duration::from_secs(AUTO_RECONNECT_INTERVAL)).await;
                        }
                    } else {
                        warn!("Daemon is online but we couldn't sync, trying again in {} seconds", AUTO_RECONNECT_INTERVAL);
                        sleep(Duration::from_secs(AUTO_RECONNECT_INTERVAL)).await;
                    }
                }
            }
        }));

        Ok(())
    }

    // Request a rescan from a specific topoheight, it will be used to rescan blocks and transactions from this topoheight
    pub async fn rescan(&self, from_topoheight: u64) -> Result<(), Error> {
        trace!("Requesting rescan from topoheight {}", from_topoheight);
        self.sender.send(NetworkHandlerMessage::Rescan { from_topoheight })
            .context("Error while sending rescan message to network handler")
            .map(|_| ())
    }

    // Request a scan for specific assets, it will be used to rescan transactions for these assets
    pub async fn scan_assets(&self, assets: HashSet<Hash>) -> Result<(), Error> {
        trace!("Requesting scan for assets {}", assets.len());
        self.sender.send(NetworkHandlerMessage::ScanAssets { assets })
            .context("Error while sending scan assets message to network handler")
            .map(|_| ())
    }

    // Stop the internal loop to stop syncing
    pub async fn stop(&self, api: bool) -> Result<(), NetworkError> {
        trace!("Stopping network handler");
        if let Some(handle) = self.task.lock().await.take() {
            if handle.is_finished() {
                debug!("Network handler is already finished");
                // We are already finished, which mean the event got triggered
                handle.await??;
            } else {
                debug!("Network handler is running, stopping it");
                if let Err(e) = self.sender.send(NetworkHandlerMessage::Stop) {
                    debug!("Error while sending stop message to network handler: {}", e);
                    handle.abort();
                } else {
                    handle.await??;
                }

                // Notify that we are offline
                self.wallet.propagate_event(Event::Offline).await;
            }

            if api {
                debug!("Network handler stopped, disconnecting api");
                // Turn off the websocket connection
                if let Err(e) = self.api.disconnect().await {
                    debug!("Error while closing websocket connection: {}", e);
                }
            }

            Ok(())
        } else {
            Err(NetworkError::NotRunning)
        }
    }

    // Retrieve the daemon API used
    pub fn get_api(&self) -> &DaemonAPI {
        &self.api
    }

    // check if the network handler is running (that we have a task and its not finished)
    pub async fn is_running(&self) -> bool {
        let task = self.task.lock().await;
        if let Some(handle) = task.as_ref() {
            !handle.is_finished() && self.api.is_online()
        } else {
            false
        }
    }

    // Process a block by checking if it contains any transaction for us
    // Or that we mined it
    // Returns assets that changed and returns the highest nonce if we send a transaction
    async fn process_block(&self, address: &Address, block: BlockResponse, topoheight: u64, handle_contracts_outputs: bool, is_rescan: bool) -> Result<Option<(HashSet<Hash>, Option<u64>)>, Error> {
        let transactions = block.transactions;
        let block = block.header;
        let block_hash = block.hash.into_owned();
        debug!("Processing block {} at topoheight {}", block_hash, topoheight);

        if block.miner.is_mainnet() != self.wallet.get_network().is_mainnet() {
            debug!("Block {} at topoheight {} is not on the same network as the wallet", block_hash, topoheight);
            return Err(NetworkError::NetworkMismatch.into())
        }

        let mut assets_changed = HashSet::new();
        // Miner address to verify if we mined the block
        let miner = block.miner.into_owned().to_public_key();
        let scan_mode = self.wallet.get_history_scan();

        // Prevent storing changes multiple times
        let mut changes_stored = false;

        // create Coinbase entry if its our address and we're looking for XELIS asset
        if miner == *address.get_public_key() {
            debug!("Block {} at topoheight {} is mined by us", block_hash, topoheight);
            if let Some(reward) = block.metadata.map(|m| m.miner_reward) {
                assets_changed.insert(XELIS_ASSET);
                
                if scan_mode.coinbase() {
                    let coinbase = EntryData::Coinbase { reward };
                    let entry = TransactionEntry::new(block_hash.clone(), topoheight, block.timestamp, coinbase);

                    let broadcast = {
                        let mut storage = self.wallet.get_storage().write().await;
    
                        // Mark it as last coinbase reward topoheight
                        // it is internally checked if its higher or not
                        debug!("Storing last coinbase reward topoheight {}", topoheight);
                        storage.set_last_coinbase_topoheight(Some(topoheight))?;

                        if storage.has_transaction(entry.get_hash())? {
                            false
                        } else {
                            storage.save_transaction(entry.get_hash(), &entry)?;
        
                            // Store the changes for history
                            if !changes_stored {
                                storage.add_topoheight_to_changes(topoheight, &block_hash)?;
                                changes_stored = true;
                            }
                            true
                        }
                    };
    
                    // Propagate the event to the wallet
                    if broadcast && !is_rescan {
                        self.wallet.propagate_event(Event::NewTransaction(entry.serializable(self.wallet.get_network().is_mainnet()))).await;
                    }
                }
            } else {
                warn!("No reward for block {} at topoheight {}", block_hash, topoheight);
            }
        }

        // Highest nonce we found in this block
        let mut our_highest_nonce = None;

        let shared_semaphores: Mutex<HashMap<Hash, Arc<Semaphore>>> = Mutex::new(HashMap::new());

        let block_hash = &block_hash;
        let shared_semaphores = &shared_semaphores;
        let results: Vec<(Option<TransactionEntry>, Option<u64>, HashSet<Hash>)> = stream::iter(transactions.into_iter())
            .map(|tx| async move {
                let mut assets_changed = HashSet::new();

                trace!("Checking transaction {}", tx.hash);
                let is_owner = *tx.source.get_public_key() == *address.get_public_key();
                let tx_nonce = if is_owner {
                    debug!("Transaction {} is from us", tx.hash);
                    assets_changed.insert(XELIS_ASSET);

                    // Check that we haven't already processed it
                    if self.wallet.has_tx_stored(&tx.hash).await? {
                        debug!("Transaction {} was already stored, skipping it", tx.hash);
                        return Ok((None, Some(tx.nonce), assets_changed));
                    }

                    Some(tx.nonce)
                } else {
                    None
                };

                // if we don't want to scan the history by decoding txs and such
                // it will simply returns none
                let entry = decoder::decode_transaction(self.wallet.as_ref(), &address, &tx, scan_mode, |asset| {
                    assets_changed.insert(asset.clone());
                    self.fetch_if_asset_not_found(asset, shared_semaphores)
                }).await?;

                let entry = if let Some(entry) = entry.filter(|_| scan_mode.all()) {
                    // Transaction found at which topoheight it was executed
                    let mut tx_topoheight = topoheight;
                    let mut tx_timestamp = block.timestamp;

                    // New transaction entry that may be linked to us, check if TX was executed
                    if !self.api.is_tx_executed_in_block(&tx.hash, &block_hash).await? {
                        debug!("Transaction {} was a good candidate but was not executed in block {}, searching its block executor", tx.hash, block_hash);
                        // Don't skip the TX, we may have missed it
                        match self.api.get_transaction_executor(&tx.hash).await {
                            Ok(executor) => {
                                tx_topoheight = executor.block_topoheight;
                                tx_timestamp = executor.block_timestamp;
                                debug!("Transaction {} was executed in block {} at topoheight {}", tx.hash, executor.block_hash, executor.block_topoheight);
                            },
                            Err(e) => {
                                // Tx is maybe not executed, this is really rare event
                                warn!("Error while fetching topoheight execution of transaction {}: {}", tx.hash, e);
                                return Ok((None, tx_nonce, assets_changed));
                            }
                        }
                    }

                    // Save the transaction
                    let entry = TransactionEntry::new(tx.hash.into_owned(), tx_topoheight, tx_timestamp, entry);

                    Some(entry)
                } else {
                    None
                };

                Ok::<_, Error>((entry, tx_nonce, assets_changed))
            })
            .boxed()
            .buffered(self.concurrency)
            .try_collect()
            .await?;

        for (entry, tx_nonce, changes) in results {
            assets_changed.extend(changes);

            // Find the highest nonce
            if let Some(tx_nonce) = tx_nonce {
                if our_highest_nonce.is_none_or(|n| tx_nonce > n) {
                    if let Some(entry) = entry.as_ref() {
                        debug!("Found new highest nonce {} in TX {}", tx_nonce, entry.get_hash());
                    }
                    our_highest_nonce = Some(tx_nonce);
                }
            }

            if let Some(entry) = entry {
                debug!("storing new entry {} from block {}", entry.get_hash(), block_hash);
                {
                    let mut storage = self.wallet.get_storage().write().await;
                    storage.save_transaction(entry.get_hash(), &entry)?;
                    // Store the changes for history
                    if !changes_stored {
                        debug!("mark topoheight {} as changed", topoheight);
                        storage.add_topoheight_to_changes(topoheight, &block_hash)?;
                        changes_stored = true;
                    }

                    // Check if the multisig state must be updated
                    if let EntryData::MultiSig { participants, threshold, .. } = entry.get_entry() {
                        let multisig = MultiSig {
                            payload: MultiSigPayload {
                                participants: participants.clone(),
                                threshold: *threshold
                            },
                            topoheight: entry.get_topoheight()
                        };
                        let store = storage.get_multisig_state().await?
                            .map(|m| m.topoheight < entry.get_topoheight())
                            .unwrap_or(true);
    
                        if store {
                            info!("Detected a multisig state change at topoheight {} from TX {}", entry.get_topoheight(), entry.get_hash());
                            if multisig.payload.is_delete() {
                                info!("Deleting multisig state");
                                storage.delete_multisig_state().await?;
                            } else {
                                info!("Updating multisig state");
                                storage.set_multisig_state(multisig).await?;
                            }
                        }
                    }
                }

                // Propagate the event to the wallet
                if !is_rescan {
                    self.wallet.propagate_event(Event::NewTransaction(entry.serializable(self.wallet.get_network().is_mainnet()))).await;
                }
            }
        }

        if handle_contracts_outputs {
            debug!("Handling contract outputs for block {} at topoheight {}", block_hash, topoheight);
            let outputs = self.api.get_contracts_outputs(address, topoheight).await?;
            let outputs_assets = self.handle_contracts_outputs(outputs.executions, topoheight, block.timestamp, is_rescan).await?;
            assets_changed.extend(outputs_assets);
        }

        // Also, verify the block version, so we handle smoothly a change in TX Version
        {
            let tx_version = block.version.get_tx_version();
            let mut storage = self.wallet.get_storage().write().await;
            if storage.get_tx_version().await? < tx_version {
                info!("Updating TX version to {}", tx_version);
                storage.set_tx_version(tx_version).await?;
            }
        }

        if (!changes_stored && !scan_mode.none()) || assets_changed.is_empty() {
            debug!("No changes found in block {} at topoheight {}, assets: {}, changes stored: {}", block_hash, topoheight, assets_changed.len(), changes_stored);
            Ok(None)
        } else {
            // Increase by one to get the new nonce
            Ok(Some((assets_changed, our_highest_nonce.map(|n| n + 1))))
        }
    }

    async fn handle_contracts_outputs(&self, outputs: HashMap<ContractTransfersEntryKey<'_>, ContractTransfersEntry<'_>>, topoheight: u64, timestamp: TimestampMillis, is_rescan: bool) -> Result<HashSet<Hash>, Error> {
        debug!("Handling contracts outputs at topoheight {}", topoheight);
        // Aggregate all transfers per transaction caller
        let mut assets = HashSet::new();
        let mut calls: HashMap<Hash, HashMap<Hash, u64>> = HashMap::new();
        for (key, entry) in outputs.into_iter() {
            debug!("Processing contract execution from caller {}", key.caller);

            assets.extend(entry.transfers.keys().cloned().map(Cow::into_owned));

            let tx_hash = key.caller.into_owned();
            let transfers = calls.entry(tx_hash)
                .or_insert_with(HashMap::new);
            for (asset, amount) in entry.transfers.into_iter() {
                debug!("Contract transfer detected: asset {}, amount {}", asset, amount);
                *transfers.entry(asset.into_owned()).or_insert(0) += amount;
            }
        }

        for (tx_hash, transfers) in calls.into_iter() {
            debug!("Updating transaction contract transfers for tx {}", tx_hash);
            self.create_or_update_transaction_contract(&tx_hash, topoheight, timestamp, transfers.into_iter(), is_rescan).await?;
        }

        Ok(assets)
    }

    // Ensure that an asset is present in storage, otherwise fetch it from daemon and store it
    // semaphores is used to prevent multiple simultaneous fetches for the same asset
    async fn fetch_if_asset_not_found<'a>(&self, asset: &'a Hash, sempahores: &Mutex<HashMap<Hash, Arc<Semaphore>>>) -> Result<(), WalletError> {
        trace!("Verifying asset {} pressence in storage", asset);

        // First check in case we already have it
        {
            let storage = self.wallet.get_storage().read().await;
            // Check if we already have this asset
            if storage.has_asset(asset).await? {
                return Ok(());
            }
        }

        // We don't have it, acquire the semaphore for this asset
        debug!("Acquiring semaphore to fetch asset {}", asset);
        let _permit = {
            let mut lock = sempahores.lock().await;

            lock.entry(asset.clone())
            .or_insert_with(|| Arc::new(Semaphore::new(1)))
            .clone()
            .acquire_owned().await?
        };

        // Check again in case we got it while waiting for the semaphore
        {
            let storage = self.wallet.get_storage().read().await;
            // Check again if we already have this asset (maybe another task fetched it while we were waiting for the semaphore)
            if storage.has_asset(asset).await? {
                return Ok(());
            }
        }

        debug!("Asset {} not found in storage, fetching it from daemon", asset);
        let data = self.api.get_asset(asset).await?;
        {
            let mut storage = self.wallet.get_storage().write().await;
            storage.add_asset(asset, data.inner).await?;
        }

        drop(_permit);

        Ok(())
    }

    // Helper method to process a single balance update with concurrent block processing
    async fn process_balance_update(&self, address: &Address, asset: Hash, mut balance: CiphertextCache, topoheight: u64, block_response: RPCBlockResponse<'static>, outputs: GetContractsOutputsResult<'static>, balances: bool, highest_version: bool, highest_nonce: Arc<Mutex<Option<u64>>>) -> Result<(), Error> {
        debug!("Processing topoheight {}, is highest {}, block {}", topoheight, highest_version, block_response.header.hash);
        let timestamp = block_response.timestamp;
        let changes = self.process_block(address, block_response, topoheight, false, true).await?;

        // It was requested at the same time of the block processing, so we can handle it now
        let assets = self.handle_contracts_outputs(outputs.executions, topoheight, timestamp, true).await?;
        trace!("Contract outputs at topoheight {} affected {} assets", topoheight, assets.len());

        // Check if a change occured, we are the highest version and update balances is requested
        if let Some((_, nonce)) = changes.filter(|_| balances && highest_version) {
            let mut storage = self.wallet.get_storage().write().await;

            // Set the highest nonce we know
            let mut highest_nonce_guard = highest_nonce.lock().await;
            if highest_nonce_guard.is_none() {
                // Get the highest nonce from storage
                debug!("Highest nonce is not set, fetching it from storage");
                *highest_nonce_guard = Some(storage.get_nonce()?);
            }

            // Store only the highest nonce
            // Because if we are building queued transactions, it may break our queue
            // Our we couldn't submit new txs before they get removed from mempool
            if let Some(nonce) = nonce.filter(|n| highest_nonce_guard.as_ref().map(|h| *h < *n).unwrap_or(true)) {
                debug!("Storing new highest nonce {}", nonce);
                storage.set_nonce(nonce)?;
                *highest_nonce_guard = Some(nonce);
            }
            drop(highest_nonce_guard);

            // If we have no balance in storage OR the stored ciphertext isn't the same, we should store it
            let store = storage.get_balance_for(&asset).await.map(|b| b.ciphertext != balance).unwrap_or(true);
            if store {
                let plaintext_balance = if let Some(plaintext_balance) = storage.get_unconfirmed_balance_decoded_for(&asset, &balance.compressed()).await? {
                    plaintext_balance
                } else {
                    trace!("Decrypting balance for asset {}", asset);
                    let ciphertext = balance.decompressed()?;
                    let max_supply = storage.get_asset(&asset).await?
                        .get_max_supply();

                    self.wallet.decrypt_ciphertext_with(ciphertext.clone(), max_supply.get_max()).await?
                        .context(format!("Couldn't decrypt the ciphertext for {} at topoheight {}", asset, topoheight))?
                };

                debug!("Storing balance from topoheight {} for asset {} ({}) {}", topoheight, asset, balance, plaintext_balance);
                // Store the new balance
                storage.set_balance_for(&asset, Balance::new(plaintext_balance, balance, topoheight)).await?;

                // Propagate the event
                self.wallet.propagate_event(Event::BalanceChanged(BalanceChanged {
                    asset,
                    balance: plaintext_balance
                })).await;
            }
        }

        Ok(())
    }

    // Scan the chain using a specific balance asset, this helps us to get a list of version to only requests blocks where changes happened
    // When the block is requested, we don't limit the syncing to asset in parameter
    async fn get_balance_and_transactions(&self, topoheight_processed: Arc<Mutex<HashSet<u64>>>, address: &Address, asset: &Hash, min_topoheight: u64, balances: bool, highest_nonce: &mut Option<u64>) -> Result<(), Error> {
        // Retrieve the highest version
        let (topoheight, version) = self.api.get_balance(address, asset).await
            .map(|res| (res.topoheight, res.version))?;

        debug!("Starting sync from topoheight {} for asset {}", topoheight, asset);

        // don't sync already synced blocks
        if min_topoheight >= topoheight {
            debug!("Reached minimum topoheight {}, topo: {}", min_topoheight, topoheight);
            return Ok(())
        }

        // Determine if its the highest version of balance or not
        // This is used to save the latest balance
        let mut highest_version = true;

        // This channel is used to send all the blocks to the processing loop
        // No more than {concurrency} blocks and versions will be prefetch in advance
        // as the task will automatically await on the channel
        let (data_sender, mut data_receiver) = mpsc::channel::<(CiphertextCache, u64, RPCBlockResponse<'static>, GetContractsOutputsResult<'static>)>(self.concurrency);
        let handle = {
            let api = self.api.clone();
            let address = address.clone();
            let asset = asset.clone();
            spawn_task("fetch-asset-versions", async move {
                let mut version = Some(version);
                let mut topoheight = topoheight;
                while let Some(v) = version.take() {
                    let start = Instant::now();
                    let block_topoheight = topoheight;
                    let (balance, _, _, previous_topoheight) = v.consume();

                    let next_topoheight = previous_topoheight.filter(|t| *t > min_topoheight);
                    if {
                        let mut lock = topoheight_processed.lock().await;
                        lock.insert(block_topoheight)
                    } {
                        trace!("fetching block with txs at {}", block_topoheight);
                        // Fetch block data, outputs, and next version concurrently
                        let (block_result, outputs_result) = if let Some(next_topo) = next_topoheight {
                            let (block, outputs, balance) = api.get_block_outputs_and_balance(block_topoheight, &address, &asset, next_topo).await?;
                            topoheight = next_topo;
                            version = Some(balance);
                            (block, outputs)
                        } else {
                            api.get_block_and_outputs(block_topoheight, &address).await?
                        };

                        data_sender.send((balance, block_topoheight, block_result, outputs_result)).await?;
                    } else if let Some(next_topo) = next_topoheight {
                        // Even if we skip this block, still fetch the next version
                        topoheight = next_topo;
                        version = Some(api.get_balance_at_topoheight(&address, &asset, next_topo).await?);
                    }

                    debug!("Fetched balance version at topoheight {} in {:?}", block_topoheight, start.elapsed());
                }

                Ok::<_, Error>(())
            })
        };

        let highest_nonce_shared = Arc::new(Mutex::new(*highest_nonce));
        let mut pending_tasks: FuturesUnordered<_> = FuturesUnordered::new();
        let mut receiver_closed = false;

        while !receiver_closed || !pending_tasks.is_empty() {
            select! {
                // Drive one pending task to completion if any are running
                Some(result) = pending_tasks.next(), if !pending_tasks.is_empty() => {
                    result?;
                },
                // Spawn a new task when we have capacity and data is available
                maybe_msg = data_receiver.recv(), if !receiver_closed && pending_tasks.len() < self.concurrency => {
                    if let Some((balance, topoheight, block, outputs)) = maybe_msg {
                        let task = Box::pin(self.process_balance_update(
                            address,
                            asset.clone(),
                            balance,
                            topoheight,
                            block,
                            outputs,
                            balances,
                            highest_version,
                            Arc::clone(&highest_nonce_shared),
                        ));
                        pending_tasks.push(task);
                        highest_version = false;
                    } else {
                        receiver_closed = true;
                    }
                },
                // Nothing to do and channel is closed, break out
                else => {
                    if receiver_closed {
                        break;
                    }
                }
            }
        }

        // Wait for any remaining tasks to complete (receiver already closed here)
        while let Some(result) = pending_tasks.next().await {
            result?;
        }
        handle.await??;

        // Update the mutable reference with the final value
        if let Some(nonce) = highest_nonce_shared.lock().await.take() {
            if highest_nonce.is_none_or(|n| nonce > n) {
                debug!("Updating highest nonce to {}", nonce);
                *highest_nonce = Some(nonce);
            }
        }

        Ok(())
    }

    // Locate the last topoheight valid for syncing, this support soft forks, DAG reorgs, etc...
    // Balances and nonce may be outdated, but we will sync them later
    // All transactions / changes above the last valid topoheight will be deleted
    // Returns daemon topoheight along wallet stable topoheight and if back sync is needed
    async fn locate_sync_topoheight_and_clean(&self) -> Result<(u64, Hash, u64), NetworkError> {
        trace!("locating sync topoheight and cleaning");
        let info = self.api.get_info().await?;
        let daemon_topoheight = info.topoheight;
        let daemon_block_hash = info.top_block_hash;
        let pruned_topoheight = info.pruned_topoheight.unwrap_or(0);

        // Verify that we are on the same network
        {
            let network = self.wallet.get_network();
            if info.network != *network {
                error!("Network mismatch! Our network is {} while daemon is {}", network, info.network);
                return Err(NetworkError::NetworkMismatch)
            }
        }

        // Check the coinbase last topoheight
        {
            let mut storage = self.wallet.get_storage().write().await;
            let last_coinbase_topoheight = storage.get_last_coinbase_topoheight();
            if let Some(last_coinbase_topoheight) = last_coinbase_topoheight {
                if last_coinbase_topoheight <= info.stable_topoheight {
                    debug!("Last coinbase reward topoheight {} is in daemon stable topoheight {}, removing it", last_coinbase_topoheight, info.stable_topoheight);
                    storage.set_last_coinbase_topoheight(None)?;
                }
            }
        }

        // Retrieve the highest point possible
        let synced_topoheight = {
            let storage = self.wallet.get_storage().read().await;

            if storage.has_top_block_hash()? {
                // Check that the daemon topoheight is the same as our
                // Verify also that the top block hash is same as our
                let top_block_hash = storage.get_top_block_hash()?;
                let synced_topoheight = storage.get_synced_topoheight()?;

                // Check if its the top
                if daemon_topoheight == synced_topoheight && daemon_block_hash == top_block_hash {
                    // No need to sync back, we are already synced
                    return Ok((daemon_topoheight, daemon_block_hash, synced_topoheight))
                }

                // Verify we are not above the daemon chain
                if synced_topoheight > daemon_topoheight {
                    warn!("We are above the daemon chain, we should sync from scratch");
                    return Ok((daemon_topoheight, daemon_block_hash, 0))
                }

                if synced_topoheight > pruned_topoheight {
                    // Check if it's still a correct block
                    let block = self.api.get_block_at_topoheight(synced_topoheight).await?;
                    let block_hash = block.header.hash.into_owned();
                    if block_hash == top_block_hash {
                        // topoheight and block hash are equal, we are still on right chain
                        return Ok((daemon_topoheight, daemon_block_hash, synced_topoheight))
                    }
                }

                synced_topoheight
            } else {
                storage.get_synced_topoheight().unwrap_or(0)
            }
        };

        // Search the highest block that is still valid for wallet
        let mut maximum = synced_topoheight;
        let block_hash = loop {
            maximum = {
                let storage = self.wallet.get_storage().read().await;
                storage.get_highest_topoheight_in_changes_below(maximum)?
            };

            // We are completely wrong, we should sync from scratch
            if maximum == 0 {
                break None;
            }

            // We are under the pruned topoheight,
            // lets assume we are on the right chain under it
            if maximum < pruned_topoheight {
                maximum = pruned_topoheight;
                break None;
            }

            // Retrieve local hash
            let local_hash = {
                let storage = self.wallet.get_storage().read().await;
                storage.get_block_hash_for_topoheight(maximum)?
            };

            // Check if we are on the same chain
            debug!("Checking if we are on the same chain at topoheight {}", maximum);
            let block = self.api.get_block_at_topoheight(maximum).await?;
            let block_hash = block.header.hash.into_owned();
            if block_hash == local_hash {
                break Some(local_hash);
            }

            // Looks like we are on a different chain
            maximum -= 1;
        };

        // Get the hash of the block at this topoheight
        let block_hash = if let Some(block_hash) = block_hash {
            block_hash
        } else {
            debug!("Fetching block hash at topoheight {}", maximum);
            match self.api.get_block_at_topoheight(maximum).await {
                Ok(block) => block.header.hash.into_owned(),
                Err(e) => {
                    error!("Error while fetching block at topoheight {}: {}, fallback to genesis", maximum, e);
                    maximum = daemon_topoheight;
                    daemon_block_hash.clone()
                }
            }
        };

        let mut storage = self.wallet.get_storage().write().await;
        // Now let's clean everything
        if storage.delete_changes_above_topoheight(maximum)? {
            warn!("Cleaning transactions above topoheight {}", maximum);
            // Changes were deleted, we should also delete transactions
            storage.delete_transactions_above_topoheight(maximum)?;
        }

        // Save the new values
        storage.set_synced_topoheight(maximum)?;
        storage.set_top_block_hash(&block_hash)?;
        // Add it only if its not already in changes
        if !storage.has_topoheight_in_changes(maximum)? {
            storage.add_topoheight_to_changes(maximum, &block_hash)?;
        }

        // Verify its not the first time we do a sync
        if synced_topoheight != 0 {
            self.wallet.propagate_event(Event::Rescan { start_topoheight: maximum }).await;   
        }

        Ok((daemon_topoheight, daemon_block_hash, maximum))
    }

    // Sync the latest version of our balances and nonces and determine if we should parse all blocks
    // If assets are provided, we'll only sync these assets
    // If nonce is not provided, we will fetch it from the daemon
    pub async fn sync_head_state(&self, address: &Address, assets: Option<&HashSet<Hash>>, nonce: Option<u64>, sync_nonce: bool, sync_multisig: bool) -> Result<bool, Error> {
        trace!("syncing head state");
        let new_nonce = if sync_nonce {
            debug!("no nonce provided, fetching it from daemon");
            match self.api.get_nonce(&address).await.map(|v| v.version) {
                Ok(v) => Some(v.get_nonce()),
                Err(e) => {
                    debug!("Error while fetching last nonce: {}", e);
                    {
                        let mut storage = self.wallet.get_storage().write().await;
                        if storage.has_any_balance().await? {
                            warn!("We have balances but we couldn't fetch the nonce, deleting all balances");
                            storage.delete_balances().await?;
                            storage.delete_assets().await?;
                            storage.delete_multisig_state().await?;
                            storage.delete_nonce().await?;
                        }
                    }

                    // Account is not registered, we can return safely here
                    return Ok(false)
                }
            }
        } else {
            nonce
        };

        // Check if we have a multisig account
        if sync_multisig {
            if self.api.has_multisig(address).await.unwrap_or(false) {
                debug!("Multisig account detected");
                let data = self.api.get_multisig(address).await?;
                if let MultisigState::Active { participants, threshold } = data.state {
                    debug!("Active multisig account with participants [{}] and threshold {}", participants.iter().map(Address::to_string).collect::<Vec<_>>().join(", "), threshold);
    
                    let payload = MultiSigPayload {
                        participants: participants.into_iter().map(|p| p.to_public_key()).collect(),
                        threshold
                    };
    
                    let multisig = MultiSig {
                        payload,
                        topoheight: data.topoheight
                    };
                    let mut storage = self.wallet.get_storage().write().await;
                    storage.set_multisig_state(multisig).await?;
                } else {
                    warn!("Multisig account is not active while marked as, skipping it");
                }
            } else {
                let mut storage = self.wallet.get_storage().write().await;
                if storage.has_multisig_state().await? {
                    info!("No multisig account detected, deleting multisig state");
                    storage.delete_multisig_state().await?;
                }
            }
        }

        let detected_assets = if let Some(assets) = assets.as_ref().filter(|a| !a.is_empty()) {
            trace!("got {} assets requested", assets.len());
            let mut references = HashSet::new();
            references.extend(assets.iter().map(Cow::Borrowed));
            references
        } else {
            trace!("no assets provided, fetching all assets");
            let mut assets = HashSet::new();
            let mut skip = 0;

            loop {
                debug!("requesting account assets, skip {}", skip);
                let response = self.api.get_account_assets(address, None, Some(skip)).await?;
                if response.is_empty() {
                    break;
                }
                skip += response.len();
                assets.extend(response.into_iter().map(Cow::Owned));
            }

            if assets.is_empty() {
                let mut storage = self.wallet.get_storage().write().await;
                if storage.has_any_asset().await? {
                    warn!("No asset detected while syncing head state, deleting local assets");
                    storage.delete_assets().await?;
                    return Ok(false)
                }
            }

            trace!("found {} assets", assets.len());

            assets
        };

        trace!("assets: {}", detected_assets.len());

        // First lets add all these new assets to our DB
        stream::iter(detected_assets.into_iter().map(Ok::<_, Error>))
            .try_for_each_concurrent(self.concurrency, |asset| async move {
                trace!("asset: {}", asset);
                // check if we have this asset locally
                if !{
                    let storage = self.wallet.get_storage().read().await;
                    storage.has_asset(&asset).await?
                } {
                    debug!("Discovered a new asset {}", asset);
                    let data = self.api.get_asset(&asset).await?;
                    // Add the asset to the storage
                    {
                        let mut storage = self.wallet.get_storage().write().await;
                        storage.add_asset(&asset, data.inner.clone()).await?;
                    }

                    // New asset detected added to the wallet, inform listeners
                    self.wallet.propagate_event(Event::NewAsset(data)).await;
                }

                Ok(())
            }).await?;

        // Now, we only sync the balances of the tracked assets
        let tracked_assets = if let Some(assets) = assets.filter(|a| !a.is_empty()) {
            let mut tracked_assets = HashSet::new();
            let storage = self.wallet.get_storage().read().await;

            for asset in assets {
                if storage.is_asset_tracked(&asset).await? {
                    tracked_assets.insert(Cow::Borrowed(asset));
                } else {
                    debug!("Asset {} was requested but its not tracked, skipping...", asset);
                }
            }

            tracked_assets
        } else {
            // Update all tracked assets
            let storage = self.wallet.get_storage().read().await;
            let iter = storage.get_tracked_assets()?;
            let mut tracked_assets = HashSet::new();

            // Only track assets that are actually available
            for res in iter {
                let asset = res?;
                if storage.has_asset(&asset).await? {
                    tracked_assets.insert(Cow::Owned(asset));
                } else {
                    debug!("Tracked asset {} is not available", asset);
                }
            }

            tracked_assets
        };

        trace!("Tracked assets: {}", tracked_assets.len());

        let mut should_sync_blocks = stream::iter(tracked_assets.iter().map(Cow::as_ref))
            .map(|asset| async move {
                trace!("requesting latest balance for {}", asset);
                // get the balance for this asset
                let result = match self.api.get_balance(&address, &asset).await {
                    Ok(res) => res,
                    Err(e) => {
                        warn!("No balance found for tracked asset {}: {}", asset, e);
                        self.wallet.propagate_event(Event::SyncError { message: format!("Error on asset {}: {}", asset, e) }).await;
                        return Ok(false)
                    }
                };
                trace!("found balance {} at topoheight: {}", asset, result.topoheight);

                let mut ciphertext = result.version.take_balance();
                let topoheight = result.topoheight;
                let (must_update, balance_cache, max_supply) = {
                    let storage = self.wallet.get_storage().read().await;
                    let must_update = match storage.get_balance_for(&asset).await {
                        Ok(mut previous) => previous.ciphertext.compressed() != ciphertext.compressed(),
                        // If we don't have a balance for this asset, we should update it
                        Err(e) => {
                            debug!("No balance found for asset {}: {}, we should update it", asset, e);
                            true
                        }
                    };

                    // If we must update, check if we have a cache for this balance
                    let balance_cache = if must_update {
                        debug!("balance for asset {} is not up-to-date, checking cache", asset);
                        storage.get_unconfirmed_balance_decoded_for(&asset, &ciphertext.compressed()).await?
                    } else {
                        None
                    };

                    let max_supply = storage.get_asset(&asset).await?
                        .get_max_supply();

                    (must_update, balance_cache, max_supply)
                };

                if must_update {
                    debug!("must update balance for asset: {}, ct: {}, cache: {:?}", asset, ciphertext, balance_cache);
                    let value = if let Some(cache) = balance_cache {
                        cache
                    } else {
                        trace!("Decrypting balance for asset {}", asset);
                        let decompressed = ciphertext.decompressed()?;
                        match self.wallet.decrypt_ciphertext_with(decompressed.clone(), max_supply.get_max()).await? {
                            Some(v) => v,
                            None => {
                                warn!("Couldn't decrypt ciphertext for asset {}, skipping it", asset);
                                return Ok::<_, Error>(false);
                            }
                        }
                    };

                    // Inform the change of the balance
                    self.wallet.propagate_event(Event::BalanceChanged(BalanceChanged {
                        asset: asset.clone(),
                        balance: value
                    })).await;

                    // Update the balance
                    let mut storage = self.wallet.get_storage().write().await;
                    debug!("Storing balance at topoheight {} for asset {} ({}) {}", topoheight, asset, value, ciphertext);
                    storage.set_balance_for(&asset, Balance::new(value, ciphertext, topoheight)).await?;

                    Ok(true)
                } else {
                    debug!("balance for asset {} is already up-to-date", asset);
                    Ok(false)
                }
            })
            .boxed()
            .buffer_unordered(self.concurrency)
            .try_fold(false, |acc, x| async move {
                Ok(acc | x)
            }).await?;

        // Apply changes
        {
            if let Some(new_nonce) = new_nonce {
                let mut storage = self.wallet.get_storage().write().await;
                if storage.get_nonce()? != new_nonce {
                    // Store the new nonce
                    debug!("Storing new nonce {}", new_nonce);
                    storage.set_nonce(new_nonce)?;
                    should_sync_blocks = true;
                }
            }
        }

        Ok(should_sync_blocks)
    }

    // Locate the highest valid topoheight we synced to, clean wallet storage
    // then sync again the head state
    async fn sync(&self, address: &Address, event: Option<NewBlockEvent>) -> Result<(), Error> {
        trace!("sync");

        // Should we sync new blocks ?
        let mut sync_new_blocks = false;

        let mut wallet_topoheight: u64;
        let mut daemon_topoheight: u64;
        let mut daemon_block_hash: Hash;

        let broadcast_history_synced = event.is_none();

        // Handle the event
        if let Some(block) = event {
            trace!("new block event received");
            // We can safely handle it by hand because `locate_sync_topoheight_and_clean` secure us from being on a wrong chain
            if let Some(topoheight) = block.header.metadata.as_ref().map(|m| m.topoheight) {
                let block_hash = block.header.hash.as_ref().clone();
                if let Some((detected_assets, mut nonce)) = self.process_block(address, block, topoheight, true, false).await
                    .context("Failed to process block")? {
                    debug!("We must sync head state, assets: {}, nonce: {:?}", detected_assets.iter().map(|a| a.to_string()).collect::<Vec<String>>().join(", "), nonce);
                    {
                        let storage = self.wallet.get_storage().read().await;
                        // Verify that its a higher nonce than our locally stored
                        // Because if we are building queued transactions, it may break our queue
                        // Our we couldn't submit new txs before they get removed from mempool
                        let stored_nonce = storage.get_nonce().unwrap_or(0);
                        if nonce.is_some_and(|n| n <= stored_nonce) {
                            debug!("Nonce {:?} is lower or equal to stored nonce {}, skipping it", nonce, stored_nonce);
                            nonce = None;
                        }
                    }

                    // A change happened in this block, lets update balance and nonce
                    self.sync_head_state(&address, Some(&detected_assets), nonce, false, false).await
                        .context("Failed to sync head state")?;

                    if nonce.is_some() {
                        // Check if we have a tx cache and clean it
                        let mut storage = self.wallet.get_storage().write().await;
                        if let Some(tx_cache) = storage.get_tx_cache() {
                            if let Some(tx) = tx_cache.last_tx_hash_created.as_ref() {
                                if storage.has_transaction(tx)? {
                                    info!("Clearing TX cache for last created tx {}", tx);
                                    storage.clear_tx_cache().await;
                                }
                            }
                        }
                    }

                    // We don't have to sync new blocks because we just processed this one
                    // And the balances were already updated with above head state sync
                    sync_new_blocks = false;
                }

                wallet_topoheight = topoheight;
                daemon_topoheight = topoheight;
                daemon_block_hash = block_hash;
            } else {
                // It is a block that got directly orphaned by DAG, ignore it
                warn!("Block {} is not ordered, skipping it", block.hash);
                return Ok(())
            }
        } else {
            debug!("No event received, verify that we are on the right chain");
            // First, locate the last topoheight valid for syncing
            (daemon_topoheight, daemon_block_hash, wallet_topoheight) = self.locate_sync_topoheight_and_clean().await
                .context("Failed to locate sync topoheight")?;
            debug!("Daemon topoheight: {}, wallet topoheight: {}", daemon_topoheight, wallet_topoheight);

            trace!("sync head state");
            // Now sync head state, this will helps us to determinate if we should sync blocks or not
            sync_new_blocks |= self.sync_head_state(&address, None, None, true, true).await
                .context("Failed to sync head state")?;
        }

        // we have something that changed, sync transactions
        // prevent a double sync head state if history scan is disabled
        if sync_new_blocks && self.wallet.get_history_scan().all() {
            // We have to loop until we are fully synced
            // Because we have a fast block time, and the wallet can be on a low-end device.
            // if the sync new blocks function takes too long, it will skip the blocks between
            // daemon topoheight and new daemon topoheight, meaning some TXs are missed
            // This can happen if you have a lot of transactions to process and the wallet is slow
            let start = Instant::now();

            // Mark the wallet as syncing
            {
                let mut storage = self.wallet.get_storage().write().await;
                storage.set_syncing(true);
            }

            loop {
                info!("Syncing new blocks from wallet topoheight {} to daemon topoheight {}", wallet_topoheight, daemon_topoheight);
                self.sync_new_blocks(address, wallet_topoheight, None, true).await?;

                // Update the topoheight and block hash for wallet
                self.update_block_reference(daemon_topoheight, &daemon_block_hash).await?;

                let (new_daemon_topoheight, new_daemon_block_hash, new_wallet_topoheight) = self.locate_sync_topoheight_and_clean().await?;
                debug!("new daemon topoheight: {}, new wallet topoheight: {}", new_daemon_topoheight, new_wallet_topoheight);

                let is_synced = daemon_topoheight >= new_daemon_topoheight;

                daemon_topoheight = new_daemon_topoheight;
                daemon_block_hash = new_daemon_block_hash;
                wallet_topoheight = new_wallet_topoheight;

                if is_synced {
                    debug!("Wallet is synced to daemon topoheight {}", new_daemon_topoheight);
                    break;
                }
            }

            info!("Sync new blocks completed in {:?}", start.elapsed());
        } else {
            // Update the topoheight and block hash for wallet
            self.update_block_reference(daemon_topoheight, &daemon_block_hash).await?;
        }

        {
            debug!("Flushing storage");
            let mut storage = self.wallet.get_storage().write().await;
            storage.set_syncing(false);
            storage.flush().await?;
            debug!("Flushed storage");
        }

        if broadcast_history_synced {
            self.wallet.propagate_event(Event::HistorySynced { topoheight: wallet_topoheight }).await;
        }

        // Propagate the event
        self.wallet.propagate_event(Event::NewTopoHeight { topoheight: daemon_topoheight }).await;
        debug!("Synced to topoheight {}", daemon_topoheight);
        Ok(())
    }

    async fn update_block_reference(&self, topoheight: u64, block_hash: &Hash) -> Result<(), Error> {
        trace!("updating block reference in storage");
        let mut storage = self.wallet.get_storage().write().await;
        storage.set_synced_topoheight(topoheight)?;
        storage.set_top_block_hash(block_hash)?;
        Ok(())
    }

    // Runs an infinite loop to sync on each new block added in chain
    // Because of potential forks and DAG reorg during attacks,
    // we verify the last valid topoheight where changes happened
    async fn start_syncing(self: &Arc<Self>) -> Result<(), Error> {
        debug!("Starting syncing");
        // Generate only one time the address
        let address = self.wallet.get_address();
        // Do a first sync to be up-to-date with the daemon
        self.sync(&address, None).await
            .context("Failed to run first sync")?;

        // Thanks to websocket, we can be notified when a new block is added in chain
        // this allows us to have a instant sync of each new block instead of polling periodically

        // Because DAG can reorder any blocks in stable height, its possible we missed some txs because they were not executed
        // when the block was added. We must check on DAG reorg for each block just to be sure
        let mut on_block_ordered = self.api.on_block_ordered_event().await?;

        // For better security, verify that an orphaned TX isn't in our ledger
        // This is rare event but may happen if someone try to do something shady
        let mut on_transaction_orphaned = self.api.on_transaction_orphaned_event().await?;

        // Track also the contract transfers to our address
        let mut on_contract_transfers = self.api.on_contract_transfers_event(address.clone()).await?;

        // Network events to detect if we are online or offline
        let mut on_connection = self.api.on_connection().await;
        let mut on_connection_lost = self.api.on_connection_lost().await;

        let mut message_recv = self.sender.subscribe();

        loop {
            select! {
                biased;
                // Wait on a new block, we don't parse the block directly as it may
                // have reorg the chain
                // Wait on a new block ordered in DAG
                res = message_recv.recv() => {
                    let message = res?;
                    match message {
                        NetworkHandlerMessage::Stop => {
                            debug!("Received stop message, stopping network handler");
                            return Ok(())
                        },
                        NetworkHandlerMessage::ScanAssets { assets } => {
                            debug!("Received scan assets message for assets: {}", assets.iter().map(|a| a.to_string()).collect::<Vec<String>>().join(", "));
                            if self.sync_head_state(&address, Some(&assets), None, false, false).await? {
                                debug!("Assets scan detected changes, syncing new blocks");
                                self.sync_new_blocks(&address, 0, Some(assets), false).await?;
                            }
                        },
                        NetworkHandlerMessage::Rescan { from_topoheight } => {
                            debug!("Received rescan message, rescanning from scratch");

                            {
                                let mut storage = self.wallet.get_storage().write().await;
                                debug!("set synced topoheight to {}", from_topoheight);
                                storage.set_synced_topoheight(from_topoheight)?;
                                storage.delete_top_block_hash()?;
                                // balances will be re-fetched from daemon
                                storage.delete_balances().await?;
                                storage.delete_assets().await?;
                                // unconfirmed balances are going to be outdated, we delete them
                                storage.delete_unconfirmed_balances().await;
                                storage.set_last_coinbase_topoheight(None)?;
                            }

                            self.sync(&address, None).await?;
                        }
                    }
                },
                res = on_block_ordered.next() => {
                    let event = res?;
                    debug!("Block ordered event {} at {}", event.block_hash, event.topoheight);
                    let topoheight = event.topoheight;
                    {
                        let mut storage = self.wallet.get_storage().write().await;
                        if let Some(hash) = storage.get_block_hash_for_topoheight(topoheight).ok() {
                            if hash != *event.block_hash {
                                warn!("DAG reorg detected at topoheight {}, deleting changes at this topoheight", topoheight);
                                storage.delete_changes_at_topoheight(topoheight)?;
                                if topoheight == 0 {
                                    debug!("Deleting all transactions due to reorg until 0");
                                    storage.delete_transactions()?;
                                } else {
                                    // Otherwise in future with millions of TXs, this may take few seconds.
                                    debug!("Deleting transactions above {} due to DAG reorg", topoheight);
                                    storage.delete_transactions_at_or_above_topoheight(topoheight)?;
                                }
                            }
                        } else {
                            debug!("No block hash found for topoheight {}, syncing block {}", topoheight, event.block_hash);
                        }
                    }

                    // TODO delete all TXs & changes at this topoheight and above
                    // We need to clean up the DB as we may have some TXs that are not executed anymore
                    // and some others that got executed

                    // Sync this block again as it may have some TXs executed
                    let block = self.api.get_block_with_txs_at_topoheight(topoheight).await?;
                    self.sync(&address, Some(block)).await?;
                },
                res = on_transaction_orphaned.next() => {
                    let event = res?;
                    debug!("on transaction orphaned event {}", event.data.hash);
                    let tx = event.data;

                    let mut storage = self.wallet.get_storage().write().await;
                    if storage.has_transaction(&tx.hash)? {
                        warn!("Transaction {} was orphaned, deleting it", tx.hash);
                        storage.delete_transaction(&tx.hash)?;
                    }

                    if storage.get_tx_cache().is_some_and(|cache| cache.last_tx_hash_created.as_ref() == Some(&tx.hash)) {
                        warn!("Transaction {} was orphaned, deleting it from cache", tx.hash);
                        storage.clear_tx_cache().await;
                    }
                },
                res = on_contract_transfers.next() => {
                    let event = res?;
                    debug!("on contract transfers event at topo {} {}", event.topoheight, event.block_hash);
                    let assets = self.handle_contracts_outputs(event.executions, event.topoheight, event.block_timestamp, false).await?;

                    // We only sync the head state if we have assets
                    // No need to sync the block because we would receive it by the on_block_ordered event
                    if !assets.is_empty() {
                        debug!("Syncing head state for {} detected assets", assets.len());
                        self.sync_head_state(&address, Some(&assets), None, false, false).await?;
                    }
                },
                // Detect network events
                res = on_connection.recv() => {
                    trace!("on_connection");
                    res?;
                    // We are connected again, make sure we are still up-to-date with node 
                    self.sync(&address, None).await?;

                    self.wallet.propagate_event(Event::Online).await;
                },
                res = on_connection_lost.recv() => {
                    trace!("on_connection_lost");
                    res?;
                    self.wallet.propagate_event(Event::Offline).await;
                }
            }
        }
    }

    async fn create_or_update_transaction_contract(&self, tx_hash: &Hash, topoheight: u64, block_timestamp: TimestampMillis, new_transfers: impl Iterator<Item = (Hash, u64)>, is_rescan: bool) -> Result<(), Error> {
        debug!("create_or_update_transaction_contract for tx {} at topoheight {}", tx_hash, topoheight);
        let mut storage = self.wallet.get_storage().write().await;
        let (mut tx, update) = if storage.has_transaction(tx_hash)? {
            (storage.get_transaction(tx_hash)?, true)
        } else {
            (TransactionEntry::new(
                tx_hash.clone(),
                topoheight,
                block_timestamp,
                EntryData::IncomingContract {
                    transfers: IndexMap::new()
                },
            ), false)
        };

        match tx.get_mut_entry() {
            EntryData::IncomingContract { transfers, .. } | EntryData::InvokeContract { received: transfers, .. } => {
                if !transfers.is_empty() {
                    debug!("transfers isn't empty, skipping existing transfers update");
                } else {
                    for (asset, amount) in new_transfers {    
                        *transfers.entry(asset.clone())
                            .or_insert(0) += amount;
                    }
    
                    if update {
                        storage.update_transaction(&tx_hash, &tx)?;
                    } else {
                        storage.save_transaction(&tx_hash, &tx)?;
                        if !is_rescan {
                            self.wallet.propagate_event(Event::NewTransaction(tx.serializable(self.wallet.get_network().is_mainnet()))).await;
                        }
                    }
                }
            },
            _ => {
                warn!("Transaction {} is not contract related, skipping it", tx_hash);
            }
        };

        Ok(())
    }

    // Sync all new blocks until the current topoheight
    // If balances is set to false, only the history will be updated
    // and not the nonce or balances
    async fn sync_new_blocks(&self, address: &Address, min_topoheight: u64, detected_assets: Option<HashSet<Hash>>, balances: bool) -> Result<(), Error> {
        debug!("Scanning history for each asset");
        // Retrieve the last transaction ID
        // We will need it to re-org all the TXs we have stored
        let (assets, last_tx_id) = {
            let storage = self.wallet.get_storage().read().await;
            let assets = if let Some(assets) = detected_assets {
                assets
            } else {
                // Only sync the tracked assets
                storage.get_tracked_assets()?
                    .collect::<Result<_, _>>()?
            };
            let last_tx_id = storage.get_last_transaction_id()?;
            (assets, last_tx_id)
        };

        // cache for all topoheight we already processed
        // this will prevent us to request more than one time the same topoheight
        let topoheight_processed = Arc::new(Mutex::new(HashSet::new()));
        let mut highest_nonce = None;
        {
            // No async stream to preserve the orders of ALL transactions
            // If we still want to run them concurrently, what we could do is:
            // - Either reorder all TXs at the reverse txs indexes below
            // - Or memory intensive: each process block returns the list of TXs
            // and each iteration below populare a BTreeMap topoheight / list of all scanned TXs
            // so we still hold the correct order, but this is discouraged to support low devices
            let topoheight_processed = &topoheight_processed;
            stream::iter(assets.into_iter())
            .for_each_concurrent(self.concurrency, |asset| {
                async move {
                    debug!("fetch history for asset {}", asset);
                    if let Err(e) = self.get_balance_and_transactions(topoheight_processed.clone(), address, &asset, min_topoheight, balances, &mut highest_nonce).await {
                        error!("Error while syncing balance for asset {}: {}", asset, e);
                        self.wallet.propagate_event(Event::SyncError { message: e.to_string() }).await;
                    }
                }
            }).await;
        }

        // We must re order all transactions indexes
        // based on their topoheight and not just reverse them
        // Because if we have asset A at topo 10, 5, and B at 11, 6
        // this will give us 10, 5, 11, 6

        // Re-org all the TXs we have stored
        {
            debug!("reverse txs indexes");
            let mut storage = self.wallet.get_storage().write().await;
            storage.reorder_transactions_indexes(last_tx_id)?;
            debug!("txs indexes reversed successfully");
        }

        Ok(())
    }
}
