use std::{sync::Arc, collections::{HashMap, HashSet}};
use thiserror::Error;
use anyhow::Error;
use log::{debug, error, warn, trace};
use tokio::{task::JoinHandle, sync::Mutex};
use xelis_common::{
    crypto::{hash::Hash, address::Address},
    block::Block,
    transaction::TransactionType,
    asset::AssetWithData,
    serializer::Serializer,
    api::{
        DataElement,
        wallet::BalanceChanged,
        daemon::{NewBlockEvent, BlockResponse}
    },
};

use crate::{
    daemon_api::DaemonAPI,
    wallet::{Wallet, Event},
    entry::{EntryData, Transfer, TransactionEntry}
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
    TaskError(#[from] tokio::task::JoinError),
    #[error(transparent)]
    DaemonAPIError(#[from] Error),
    #[error("Network mismatch")]
    NetworkMismatch,
    #[error("Daemon is not synced, we are higher than daemon")]
    DaemonNotSynced
}

pub struct NetworkHandler {
    // tokio task
    task: Mutex<Option<JoinHandle<Result<(), Error>>>>,
    // wallet where we can save every data from chain
    wallet: Arc<Wallet>,
    // api to communicate with daemon
    api: DaemonAPI
}

impl NetworkHandler {
    pub async fn new<S: ToString>(wallet: Arc<Wallet>, daemon_address: S) -> Result<SharedNetworkHandler, Error> {
        let api = DaemonAPI::new(format!("{}/json_rpc", daemon_address.to_string())).await?;
        // check that we can correctly get version from daemon
        let version = api.get_version().await?;
        debug!("Connected to daemon running version {}", version);

        Ok(Arc::new(Self {
            task: Mutex::new(None),
            wallet,
            api
        }))
    }

    // Start the internal loop to sync all missed blocks and all newly added blocks
    pub async fn start(self: &Arc<Self>) -> Result<(), NetworkError> {
        if self.is_running().await {
            return Err(NetworkError::AlreadyRunning)
        }

        let zelf = Arc::clone(&self);
        *self.task.lock().await = Some(tokio::spawn(async move {
            let res =  zelf.start_syncing().await;
            if let Err(e) = res.as_ref() {
                error!("Error while syncing: {}", e);
            }

            // Notify that we are offline
            zelf.wallet.propagate_event(Event::Offline).await;

            res
        }));


        // Notify that we are online
        self.wallet.propagate_event(Event::Online).await;

        Ok(())
    }

    // Stop the internal loop to stop syncing
    pub async fn stop(&self) -> Result<(), NetworkError> {
        trace!("Stopping network handler");
        if let Some(handle) = self.task.lock().await.take() {
            if handle.is_finished() {
                // We are already finished, which mean the event got triggered
                handle.await??;
            } else {
                handle.abort();

                // Notify that we are offline
                self.wallet.propagate_event(Event::Offline).await;
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
    async fn process_block(&self, address: &Address, block_response: BlockResponse<'_, Block>, topoheight: u64) -> Result<bool, Error> {
        let block = block_response.data.data.into_owned();
        let block_hash = block_response.data.hash.into_owned();

        let mut changes_stored = false;
        // create Coinbase entry if its our address and we're looking for XELIS asset
        if *block.get_miner() == *address.get_public_key() {
            if let Some(reward) = block_response.reward {
                let coinbase = EntryData::Coinbase(reward);
                let entry = TransactionEntry::new(block_hash.clone(), topoheight, None, None, coinbase);

                {
                    let mut storage = self.wallet.get_storage().write().await;
                    storage.save_transaction(entry.get_hash(), &entry)?;

                    // Store the changes for history
                    if !changes_stored {
                        storage.add_topoheight_to_changes(topoheight, &block_hash)?;
                        changes_stored = true;
                    }
                }

                // Propagate the event to the wallet
                self.wallet.propagate_event(Event::NewTransaction(entry)).await;
            } else {
                warn!("No reward for block {} at topoheight {}", block_hash, topoheight);
            }
        }

        // Verify all TXs one by one to find one for us
        let (block, txs) = block.split();
        for (tx_hash, tx) in block.into_owned().take_txs_hashes().into_iter().zip(txs) {
            let tx = tx.into_owned();
            let is_owner = *tx.get_owner() == *address.get_public_key();
            let fee = if is_owner { Some(tx.get_fee()) } else { None };
            let nonce = if is_owner { Some(tx.get_nonce()) } else { None };
            let (owner, data) = tx.consume();
            let entry: Option<EntryData> = match data {
                TransactionType::Burn { asset, amount } => {
                    if is_owner {
                        Some(EntryData::Burn { asset, amount })
                    } else {
                        None
                    }
                },
                TransactionType::Transfer(txs) => {
                    let mut transfers: Vec<Transfer> = Vec::new();
                    for tx in txs {
                        if is_owner || tx.to == *address.get_public_key() {
                            let extra_data = tx.extra_data.and_then(|bytes| DataElement::from_bytes(&bytes).ok());
                            let transfer = Transfer::new(tx.to, tx.asset, tx.amount, extra_data);
                            transfers.push(transfer);
                        }
                    }

                    if is_owner { // check that we are owner of this TX
                        Some(EntryData::Outgoing(transfers))
                    } else if !transfers.is_empty() { // otherwise, check that we received one or few transfers from it
                        Some(EntryData::Incoming(owner, transfers))
                    } else { // this TX has nothing to do with us, nothing to save
                        None
                    }
                },
                _ => {
                    error!("Transaction type not supported");
                    None
                }
            };

            if let Some(entry) = entry {
                // New transaction entry that may be linked to us, check if TX was executed
                if !self.api.is_tx_executed_in_block(&tx_hash, &block_hash).await? {
                    debug!("Transaction {} was a good candidate but was not executed in block {}, skipping", tx_hash, block_hash);
                    continue;
                }

                let entry = TransactionEntry::new(tx_hash, topoheight, fee, nonce, entry);
                let propagate = {
                    let mut storage = self.wallet.get_storage().write().await;
                    let found = storage.has_transaction(entry.get_hash())?;
                    if !found {
                        storage.save_transaction(entry.get_hash(), &entry)?;
                        // Store the changes for history
                        if !changes_stored {
                            storage.add_topoheight_to_changes(topoheight, &block_hash)?;
                            changes_stored = true;
                        }
                    }
                    !found
                };

                if propagate {
                    // Propagate the event to the wallet
                    self.wallet.propagate_event(Event::NewTransaction(entry)).await;
                }
            }
        }

        Ok(changes_stored)
    }

    // Scan the chain using a specific balance asset, this helps us to get a list of version to only requests blocks where changes happened
    // When the block is requested, we don't limit the syncing to asset in parameter
    async fn get_balance_and_transactions(&self, topoheight_processed: &mut HashSet<u64>, address: &Address, asset: &Hash, min_topoheight: u64, balances: bool) -> Result<(), Error> {
        // Retrieve the highest version
        let (mut topoheight, mut version) = self.api.get_balance(address, asset).await.map(|res| (res.topoheight, res.version))?;
        // don't sync already synced blocks
        if min_topoheight >= topoheight {
            return Ok(())
        }

        // Determine if its the highest version of balance or not
        // This is used to save the latest balance
        let mut highest_version = true;
        loop {
            // add this topoheight in cache to not re-process it (blocks are independant of asset to have faster sync)
            // if its not already processed, do it
            if topoheight_processed.insert(topoheight) {
                let response = self.api.get_block_with_txs_at_topoheight(topoheight).await?;
                let changes = self.process_block(address, response, topoheight).await?;

                // Check if a change occured, we are the highest version and update balances is requested
                if balances && highest_version && changes {
                    let mut storage = self.wallet.get_storage().write().await;
                    let previous_balance = storage.get_balance_for(asset).unwrap_or(0);
                    let new_balance = version.get_balance();
                    if previous_balance != new_balance {
                        storage.set_balance_for(asset, new_balance)?;
                        // Propagate the event
                        self.wallet.propagate_event(Event::BalanceChanged(BalanceChanged {
                            asset: asset.clone(),
                            balance: new_balance
                        })).await;
                    }
                }
            }

            // Prepare a new iteration
            if let Some(previous) = version.get_previous_topoheight() {
                // don't sync already synced blocks
                if min_topoheight >= previous {
                    return Ok(())
                }

                topoheight = previous;
                version = self.api.get_balance_at_topoheight(address, asset, previous).await?;
            } else {
                return Ok(())
            }

            // Only first iteration is the highest one
            highest_version = false;
        }
    }

    // Locate the last topoheight valid for syncing, this support soft forks, DAG reorgs, etc...
    // Balances and nonce may be outdated, but we will sync them later
    // All transactions / changes above the last valid topoheight will be deleted
    // Returns daemon topoheight along wallet stable topoheight and if back sync is needed
    async fn locate_sync_topoheight_and_clean(&self) -> Result<(u64, Hash, u64, bool), NetworkError> {
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
                    return Ok((daemon_topoheight, daemon_block_hash, synced_topoheight, false))
                }

                // Verify we are not above the daemon chain
                if synced_topoheight > info.topoheight {
                    return Err(NetworkError::DaemonNotSynced)
                }

                if synced_topoheight > pruned_topoheight {
                    // Check if it's still a correct block
                    let header = self.api.get_block_at_topoheight(synced_topoheight).await?;
                    let block_hash = header.data.hash.into_owned();
                    if block_hash == top_block_hash {
                        // topoheight and block hash are equal, we are still on right chain
                        return Ok((daemon_topoheight, daemon_block_hash, synced_topoheight, false))
                    }
                }

                synced_topoheight
            } else {
                0
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
            let header = self.api.get_block_at_topoheight(maximum).await?;
            let block_hash = header.data.hash.into_owned();
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
            let response = self.api.get_block_at_topoheight(maximum).await?;
            response.data.hash.into_owned()
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
            self.wallet.propagate_event(Event::Rescan(maximum)).await;   
        }

        Ok((daemon_topoheight, daemon_block_hash, maximum, true))
    }

    // Sync the latest version of our balances and nonces and determine if we should parse all blocks
    async fn sync_head_state(&self, address: &Address) -> Result<bool, Error> {
        let versioned_nonce = match self.api.get_nonce(&address).await.map(|v| v.version) {
            Ok(v) => v,
            Err(e) => {
                debug!("Error while fetching last nonce: {}", e);
                // Account is not registered, we can return safely here
                return Ok(false)
            }
        };

        let assets = self.api.get_account_assets(&address).await?;
        let mut balances = HashMap::new();
        for asset in &assets {
            // check if we have this asset locally
            if !{
                let storage = self.wallet.get_storage().read().await;
                storage.contains_asset(&asset)?
            } {
                let data = self.api.get_asset(&asset).await?;
                
                // Add the asset to the storage
                {
                    let mut storage = self.wallet.get_storage().write().await;
                    storage.add_asset(&asset, data.get_decimals())?;
                }

                // New asset added to the wallet, inform listeners
                self.wallet.propagate_event(Event::NewAsset(AssetWithData::new(asset.clone(), data))).await;
            }

            // get the balance for this asset
            let balance = self.api.get_balance(&address, &asset).await.map(|v| v.version)?;
            balances.insert(asset, balance.get_balance());
        }

        let mut should_sync_blocks = false;
        // Apply changes
        {
            let mut storage = self.wallet.get_storage().write().await;
            let new_nonce = versioned_nonce.get_nonce();
            if new_nonce != storage.get_nonce().unwrap_or(0) {
                // Store the new nonce
                storage.set_nonce(new_nonce)?;
                should_sync_blocks = true;
            }

            for (asset, value) in balances {
                let must_update = match storage.get_balance_for(&asset) {
                    Ok(previous) => previous != value,
                    // If we don't have a balance for this asset, we should update it
                    Err(_) => true
                };

                if must_update {
                    // Inform the change of the balance
                    self.wallet.propagate_event(Event::BalanceChanged(BalanceChanged {
                        asset: asset.clone(),
                        balance: value
                    })).await;

                    // Update the balance
                    storage.set_balance_for(asset, value)?;

                    // We should sync new blocks to get the TXs
                    should_sync_blocks = true;
                }
            }
        }

        Ok(should_sync_blocks)
    }

    // Locate the highest valid topoheight we synced to, clean wallet storage
    // then sync again the head state
    async fn sync(&self, address: &Address, event: Option<NewBlockEvent>) -> Result<(), Error> {
        // First, locate the last topoheight valid for syncing
        let (daemon_topoheight, daemon_block_hash, wallet_topoheight, sync_back) = self.locate_sync_topoheight_and_clean().await?;

        // Sync back is requested, sync the head state again
        if sync_back {
            // Now sync head state, this will helps us to determinate if we should sync blocks or not
            let should_sync_blocks = self.sync_head_state(&address).await?;
            // we have something that changed, sync transactions
            if should_sync_blocks {
                self.sync_new_blocks(&address, wallet_topoheight, false).await?;
            }
        } else if daemon_topoheight > wallet_topoheight {
            // We didn't had to resync, sync only necessary blocks
            if let Some(block) = event {
                // We can safely handle it by hand by `locate_sync_topoheight_and_clean` secure us from being on a wrong chain
                if let Some(topoheight) = block.topoheight {
                    if self.process_block(address, block, topoheight).await? {
                        // A change happened in this block, lets update balance and nonce
                        self.sync_head_state(&address).await?;
                    }
                } else {
                    // It is a block that got directly orphaned by DAG, ignore it
                    debug!("Block {} is not ordered, skipping it", block.data.hash);
                }
                // TODO handle block event
            } else {
                // No event, sync blocks by hand
                self.sync_new_blocks(address, wallet_topoheight, true).await?;
            }
        }

        // Update the topoheight and block hash for wallet
        {
            let mut storage = self.wallet.get_storage().write().await;
            storage.set_synced_topoheight(daemon_topoheight)?;
            storage.set_top_block_hash(&daemon_block_hash)?;
        }

        // Propagate the event
        self.wallet.propagate_event(Event::NewTopoHeight(daemon_topoheight)).await;
        debug!("Synced to topoheight {}", daemon_topoheight);
        Ok(())
    }

    // Runs an infinite loop to sync on each new block added in chain
    // Because of potential forks and DAG reorg during attacks,
    // we verify the last valid topoheight where changes happened
    async fn start_syncing(self: &Arc<Self>) -> Result<(), Error> {
        // Generate only one time the address
        let address = self.wallet.get_address();
        // Do a first sync to be up-to-date with the daemon
        self.sync(&address, None).await?;

        // Thanks to websocket, we can be notified when a new block is added in chain
        // this allows us to have a instant sync of each new block instead of polling periodically
        let mut receiver = self.api.on_new_block_event().await?;

        // Network events to detect if we are online or offline
        let mut on_connection = self.api.on_connection().await;
        let mut on_connection_lost = self.api.on_connection_lost().await;

        loop {
            tokio::select! {
                // Wait on a new block, we don't parse the block directly as it may
                // have reorg the chain
                res = receiver.next() => {
                    let event = res?;
                    self.sync(&address, Some(event)).await?;
                },
                // Detect network events
                res = on_connection.recv() => {
                    res?;
                    self.wallet.propagate_event(Event::Online).await;
                },
                res = on_connection_lost.recv() => {
                    res?;
                    self.wallet.propagate_event(Event::Offline).await;
                }
            }
        }
    }

    // Sync all new blocks until the current topoheight
    async fn sync_new_blocks(&self, address: &Address, current_topoheight: u64, balances: bool) -> Result<(), Error> {
        let assets = {
            let storage = self.wallet.get_storage().read().await;
            storage.get_assets()?
        };

        // cache for all topoheight we already processed
        // this will prevent us to request more than one time the same topoheight
        let mut topoheight_processed = HashSet::new();

        // get balance and transactions for each asset
        for asset in assets {
            debug!("calling get balances and transactions {}", current_topoheight);
            if let Err(e) = self.get_balance_and_transactions(&mut topoheight_processed, &address, &asset, current_topoheight, balances).await {
                error!("Error while syncing balance for asset {}: {}", asset, e);
            }
        }
        Ok(())
    }
}