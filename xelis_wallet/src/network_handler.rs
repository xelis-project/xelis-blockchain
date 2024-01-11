use std::{sync::{Arc, atomic::{AtomicBool, Ordering}}, collections::HashMap};
use thiserror::Error;
use anyhow::Error;
use log::{debug, error, warn};
use tokio::{task::JoinHandle, sync::Mutex};
use xelis_common::{
    crypto::{hash::Hash, address::Address},
    block::Block,
    transaction::TransactionType,
    asset::AssetWithData,
    serializer::Serializer,
    api::{
        DataElement,
        wallet::BalanceChanged
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
    api: DaemonAPI,
    // used in case the daemon is not responding but we're already connected
    is_paused: AtomicBool
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
            api,
            is_paused: AtomicBool::new(false)
        }))
    }

    pub async fn start(self: &Arc<Self>) -> Result<(), NetworkError> {
        if self.is_running().await {
            return Err(NetworkError::AlreadyRunning)
        }

        let zelf = Arc::clone(&self);
        *self.task.lock().await = Some(tokio::spawn(async move {
            if let Err(e) = zelf.start_syncing().await {
                error!("Error while syncing: {}", e);
            }
            Ok(())
        }));

        Ok(())
    }

    pub async fn stop(&self) -> Result<(), NetworkError> {
        if let Some(handle) = self.task.lock().await.take() {
            if handle.is_finished() {
                handle.await??;
            } else {
                handle.abort();
            }
            Ok(())
        } else {
            Err(NetworkError::NotRunning)
        }
    }

    pub fn get_api(&self) -> &DaemonAPI {
        &self.api
    }

    // check if the network handler is running (that we have a task and its not finished)
    pub async fn is_running(&self) -> bool {
        let task = self.task.lock().await;
        if let Some(handle) = task.as_ref() {
            !handle.is_finished() && !self.is_paused()
        } else {
            false
        }
    }

    fn is_paused(&self) -> bool {
        self.is_paused.load(Ordering::SeqCst)
    }

    async fn get_balance_and_transactions(&self, address: &Address, asset: &Hash, min_topoheight: u64) -> Result<(), Error> {
        // Retrieve the highest version
        let (mut topoheight, mut version) = self.api.get_balance(address, asset).await.map(|res| (res.topoheight, res.version))?;
        loop {
            // don't sync already synced blocks
            if min_topoheight >= topoheight {
                return Ok(())
            }

            let mut changes_stored = false;
            let response = self.api.get_block_with_txs_at_topoheight(topoheight).await?;
            let block: Block = response.data.data.into_owned();
            let block_hash = response.data.hash.into_owned();

            // create Coinbase entry if its our address and we're looking for XELIS asset
            if *block.get_miner() == *address.get_public_key() {
                if let Some(reward) = response.reward {
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
                        found
                    };

                    if propagate {
                        // Propagate the event to the wallet
                        self.wallet.propagate_event(Event::NewTransaction(entry)).await;
                    }
                }
            }

            if let Some(previous) = version.get_previous_topoheight() {
                version = self.api.get_balance_at_topoheight(address, asset, previous).await?;
                topoheight = previous;
            } else {
                return Ok(())
            }
        }
    }

    // Locate the last topoheight valid for syncing, this support soft forks, DAG reorgs, etc...
    // Balances and nonce may be outdated, but we will sync them later
    // All transactions / changes above the last valid topoheight will be deleted
    // Returns daemon topoheight along wallet stable topoheight
    async fn locate_sync_topoheight_and_clean(&self) -> Result<(u64, Hash, u64), NetworkError> {
        let info = self.api.get_info().await?;
        let daemon_topoheight = info.topoheight;
        let daemon_block_hash = info.top_block_hash;

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
                    return Ok((daemon_topoheight, daemon_block_hash, synced_topoheight))
                }

                // Verify we are not above the daemon chain
                if synced_topoheight > info.topoheight {
                    return Err(NetworkError::DaemonNotSynced)
                }

                // Check if it's still a correct block
                let header = self.api.get_block_at_topoheight(synced_topoheight).await?;
                let block_hash = header.data.hash.into_owned();
                if block_hash == top_block_hash {
                    // topoheight and block hash are equal, we are still on right chain
                    return Ok((daemon_topoheight, daemon_block_hash, synced_topoheight))
                }

                synced_topoheight
            } else {
                0
            }
        };

        // Search the highest block that is still valid for wallet
        let mut maximum = synced_topoheight;
        let mut minimum = info.pruned_topoheight.unwrap_or(0);
        while minimum <= maximum {
            let middle = (minimum + maximum) / 2;
            if middle == 0 {
                // we are at the genesis block, we can't go lower
                break;
            }

            // get the highest hash we have locally that we synced
            let local_hash = {
                let storage = self.wallet.get_storage().read().await;
                // check if we have a changes that happened in this block locally
                let Ok(hash) = storage.get_block_hash_for_topoheight(middle) else {
                    maximum = middle - 1;
                    continue;
                };
                hash
            };

            // Request the daemon to get the block at this topoheight
            let block = self.api.get_block_at_topoheight(middle).await?;
            let block_hash = block.data.hash.into_owned();

            if block_hash == local_hash {
                // we have this block, increase minimum
                minimum = middle + 1;
            } else {
                // we don't have this block, decrease maximum
                maximum = middle - 1;
            }
        }

        // Reduce the minimum by one to get the last block we have
        if minimum != 0 {
            minimum -= 1;
        }

        // Get the hash of the block at this topoheight
        let block_hash = self.api.get_block_at_topoheight(minimum).await?.data.hash.into_owned();
        let mut storage = self.wallet.get_storage().write().await;        
        // Now let's clean everything
        storage.delete_transactions_above_topoheight(minimum)?;
        storage.delete_changes_above_topoheight(minimum)?;

        // Save the new values
        storage.set_synced_topoheight(minimum)?;
        storage.set_top_block_hash(&block_hash)?;
        storage.add_topoheight_to_changes(minimum, &block_hash)?;

        Ok((daemon_topoheight, daemon_block_hash, minimum))
    }

    // TODO returns hashset of topoheight to scan for txs ?
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

    async fn sync(&self) -> Result<(), Error> {
        // First, locate the last topoheight valid for syncing
        let (daemon_topoheight, daemon_block_hash, wallet_topoheight) = self.locate_sync_topoheight_and_clean().await?;

        // Now sync head state, this will helps us to determinate if we should sync blocks or not
        let address = self.wallet.get_address();
        let should_sync_blocks = self.sync_head_state(&address).await?;
        // Store the changes for history

        if should_sync_blocks {
            self.sync_new_blocks(&address, wallet_topoheight).await?;
        }

        // Update the topoheight and block hash for wallet
        {
            let mut storage = self.wallet.get_storage().write().await;
            storage.set_synced_topoheight(daemon_topoheight)?;
            storage.set_top_block_hash(&daemon_block_hash)?;
            storage.add_topoheight_to_changes(daemon_topoheight, &daemon_block_hash)?;
        }

        Ok(())
    }

    // TODO
    async fn start_syncing(self: Arc<Self>) -> Result<(), Error> {
        // Sync a first time
        self.sync().await?;

        let mut receiver = self.api.on_new_block_event().await?;
        loop {
            let _ = receiver.next().await?;
            self.sync().await?;
        }
    }

    async fn sync_new_blocks(&self, address: &Address, current_topoheight: u64) -> Result<(), Error> {
        let assets = {
            let storage = self.wallet.get_storage().read().await;
            storage.get_assets()?
        };

        // get balance and transactions for each asset
        for asset in assets {
            debug!("calling get balances and transactions {}", current_topoheight);
            if let Err(e) = self.get_balance_and_transactions(&address, &asset, current_topoheight).await {
                error!("Error while syncing balance for asset {}: {}", asset, e);
            }
        }
        Ok(())
    }
}