use std::{sync::{Arc, atomic::{AtomicBool, Ordering}}, time::Duration};
use thiserror::Error;
use anyhow::Error;
use log::{debug, error, info, warn};
use tokio::{task::JoinHandle, sync::Mutex, time::interval};
use xelis_common::{crypto::{hash::Hash, address::Address}, block::Block, transaction::TransactionType, account::VersionedBalance, asset::AssetWithData, serializer::Serializer, api::DataElement, config::XELIS_ASSET};

use crate::{daemon_api::DaemonAPI, wallet::{Wallet, Event}, entry::{EntryData, Transfer, TransactionEntry}};

#[cfg(feature = "api_server")]
use {
    std::borrow::Cow,
    xelis_common::api::wallet::{NotifyEvent, BalanceChanged}
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
    DaemonAPIError(#[from] Error)
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

// how many assets we get by request
const MAX_ASSETS: usize = 64;

impl NetworkHandler {
    pub async fn new<S: ToString>(wallet: Arc<Wallet>, daemon_address: S) -> Result<SharedNetworkHandler, Error> {
        let api = DaemonAPI::new(format!("{}/json_rpc", daemon_address.to_string()));
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
        *self.task.lock().await = Some(tokio::spawn(zelf.start_syncing()));

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

    async fn get_versioned_balance_and_topoheight(&self, address: &Address, asset: &Hash, current_topoheight: Option<u64>) -> Result<Option<(u64, VersionedBalance)>, Error> {
        let (topoheight, balance) = match &current_topoheight {
            Some(topoheight) => (*topoheight, self.api.get_balance_at_topoheight(address, asset, *topoheight).await?),
            None => { // try to get last balance
                let res = match self.api.get_last_balance(&address, asset).await {
                    Ok(res) => res,
                    Err(e) => { // balance doesn't exist on chain for this asset
                        debug!("Error while getting last balance: {}", e);
                        return Ok(None)
                    }
                };
                let balance = res.balance;

                // Inform the change of the balance
                #[cfg(feature = "api_server")]
                {
                    if let Some(api_server) = self.wallet.get_api_server().lock().await.as_ref() {
                        api_server.notify_event(&NotifyEvent::BalanceChanged, &BalanceChanged {
                            asset: Cow::Borrowed(&asset),
                            balance: balance.get_balance()
                        }).await;
                    }
                }

                self.wallet.propagate_event(Event::BalanceChanged(asset.clone(), balance.get_balance())).await;

                // lets write the final balance
                let mut storage = self.wallet.get_storage().write().await;
                storage.set_balance_for(asset, balance.get_balance())?;

                (res.topoheight, balance)
            }
        };
        Ok(Some((topoheight, balance)))
    }

    async fn get_balance_and_transactions(&self, address: &Address, asset: &Hash, min_topoheight: u64, current_topoheight: Option<u64>) -> Result<(), Error> {
        let mut res = self.get_versioned_balance_and_topoheight(address, asset, current_topoheight).await?;
        while let Some((topoheight, balance)) = res.take() {
            // don't sync already synced blocks
            if min_topoheight > topoheight {
                return Ok(())
            }

            let response = self.api.get_block_with_txs_at_topoheight(topoheight).await?;
            let block: Block = response.data.data.into_owned();
            let block_hash = response.data.hash.into_owned();

            // create Coinbase entry if its our address and we're looking for XELIS asset
            if *asset == XELIS_ASSET && *block.get_miner() == *address.get_public_key() {
                if let Some(reward) = response.reward {
                    let coinbase = EntryData::Coinbase(reward);
                    let entry = TransactionEntry::new(block_hash.clone(), topoheight, None, None, coinbase);

                    // New coinbase entry, inform listeners
                    #[cfg(feature = "api_server")]
                    {
                        if let Some(api_server) = self.wallet.get_api_server().lock().await.as_ref() {
                            api_server.notify_event(&NotifyEvent::NewTransaction, &entry).await;
                        }
                    }

                    let mut storage = self.wallet.get_storage().write().await;
                    storage.save_transaction(entry.get_hash(), &entry)?;

                    self.wallet.propagate_event(Event::NewTransaction(entry)).await;
                } else {
                    warn!("No reward for block {} at topoheight {}", block_hash, topoheight);
                }
            }

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
                    let mut storage = self.wallet.get_storage().write().await;

                    if !storage.has_transaction(entry.get_hash())? {
                        // notify listeners of new transaction
                        #[cfg(feature = "api_server")]
                        {
                            if let Some(api_server) = self.wallet.get_api_server().lock().await.as_ref() {
                                api_server.notify_event(&NotifyEvent::NewTransaction, &entry).await;
                            }
                        }

                        storage.save_transaction(entry.get_hash(), &entry)?;

                        // Propagate the event to the wallet
                        self.wallet.propagate_event(Event::NewTransaction(entry)).await;
                    }
                }
            }

            if let Some(previous_topo) = balance.get_previous_topoheight() {
                res = self.get_versioned_balance_and_topoheight(address, asset, Some(previous_topo)).await?;
            }
        }

        Ok(())
    }

    // start syncing the wallet with data from daemon API
    // we get all assets registered on chain and check their balance
    // we also check if there is a balance change at a previous topoheight
    // if there is, we get the balance at this topoheight and check if there is a previous topoheight
    // we do this until we reach the first topoheight
    // at first time only, retrieve the saved nonce of this account (or when a tx out is detected)
    async fn start_syncing(self: Arc<Self>) -> Result<(), Error> {
        let address = self.wallet.get_address();
        let (mut current_topoheight, mut top_block_hash) = {
            let storage = self.wallet.get_storage().read().await;
            (storage.get_daemon_topoheight().unwrap_or(0), storage.get_top_block_hash().unwrap_or(Hash::zero()))
        };
        let mut interval = interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            // get infos from chain
            // TODO compare them with already stored to not resync fully each time
            let info = match self.api.get_info().await {
                Ok(info) => info,
                Err(e) => {
                    debug!("Impossible to sync new blocks: {}", e);
                    if !self.is_paused() { // show message only one time per disconnecting
                        error!("Impossible to sync new blocks, daemon is not reachable");
                        self.is_paused.store(true, Ordering::SeqCst);
                    }
                    continue;
                }
            };

            {
                let network = self.wallet.get_network();
                if info.network != *network {
                    error!("Network mismatch! Our network is {} while daemon is {}", network, info.network);
                    return Ok(())
                }
            }
            // we are in paused mode, but we can connect again to daemon
            if self.is_paused() {
                info!("Daemon is reachable again, syncing...");
                self.is_paused.store(false, Ordering::SeqCst);
            }

            debug!("current topoheight: {}, info topoheight: {}", info.topoheight, current_topoheight);
            if info.topoheight == current_topoheight {
                if current_topoheight != 0 && info.top_block_hash != top_block_hash {
                    // Looks like we are on a fork, we need to resync from the top
                    let mut storage = self.wallet.get_storage().write().await;
                    storage.delete_transactions_above_topoheight(current_topoheight - 1)?;
                } else {
                    continue;
                }
            }
            debug!("New topoheight detected for chain: {}", info.topoheight);

            // New get_info with different topoheight, inform listeners
            #[cfg(feature = "api_server")]
            {
                if let Some(api_server) = self.wallet.get_api_server().lock().await.as_ref() {
                    api_server.notify_event(&NotifyEvent::NewChainInfo, &info).await;
                }
            }

            self.wallet.propagate_event(Event::NewTopoHeight(info.topoheight)).await;
            top_block_hash = info.top_block_hash;

            if let Err(e) = self.sync_new_blocks(&address, current_topoheight, info.topoheight).await {
                error!("Error while syncing new blocks: {}", e);
            }

            // save current topoheight in daemon
            {
                debug!("Saving current topoheight daemon: {}", current_topoheight);
                let mut storage = self.wallet.get_storage().write().await;
                storage.set_daemon_topoheight(info.topoheight)?;
                storage.set_top_block_hash(&top_block_hash)?;
            }
            current_topoheight = info.topoheight;
        }
    }

    async fn sync_new_blocks(&self, address: &Address, current_topoheight: u64, network_topoheight: u64) -> Result<(), Error> {
        let mut assets = {
            let storage = self.wallet.get_storage().read().await;
            storage.get_assets()?
        };

        // fetch all new assets from chain
        {
            let mut has_next = true;
            let mut skip = 0;
            // Loop until we got all assets
            while has_next {
                let response = self.api.get_assets(Some(skip), Some(MAX_ASSETS), Some(current_topoheight), Some(network_topoheight)).await?;
                // if the response is full that may mean we have another page to read
                has_next = response.len() == MAX_ASSETS;
                skip += response.len();
    
                let mut storage = self.wallet.get_storage().write().await;
                for asset_data in &response {
                    if !storage.contains_asset(asset_data.get_asset())? {
                        // New asset added to the wallet, inform listeners
                        #[cfg(feature = "api_server")]
                        {
                            if let Some(api_server) = self.wallet.get_api_server().lock().await.as_ref() {
                                api_server.notify_event(&NotifyEvent::NewAsset, asset_data).await;
                            }
                        }

                        storage.add_asset(asset_data.get_asset(), asset_data.get_data().get_decimals())?;
                    }
                }
    
                assets.extend(response.into_iter().map(AssetWithData::to_asset).collect::<Vec<_>>());
            }
        }

        // Retrieve the highest nonce (in one call, in case of assets/txs not tracked correctly)
        {
            let nonce = self.api.get_last_nonce(&address).await.map(|v| v.version.get_nonce()).unwrap_or(0);
            debug!("New nonce found is {}", nonce);
            let mut storage = self.wallet.get_storage().write().await;
            storage.set_nonce(nonce)?;
        }

        // get balance and transactions for each asset
        for asset in assets {
            debug!("calling get balances and transactions {}", current_topoheight);
            if let Err(e) = self.get_balance_and_transactions(&address, &asset, current_topoheight, None).await {
                error!("Error while syncing balance for asset {}: {}", asset, e);
            }
        }
        Ok(())
    }
}