use std::{sync::{Arc, atomic::{AtomicBool, Ordering}}, time::Duration};
use thiserror::Error;
use anyhow::Error;
use log::{debug, error, info};
use tokio::{task::JoinHandle, sync::Mutex, time::interval};
use xelis_common::{crypto::{hash::Hash, address::Address}, block::CompleteBlock, transaction::TransactionType, account::VersionedBalance};

use crate::{api::DaemonAPI, wallet::Wallet, entry::{EntryData, Transfer, TransactionEntry}};

// NetworkHandler must be behind a Arc to be accessed from Wallet (to stop it) or from tokio task
pub type SharedNetworkHandler = Arc<NetworkHandler>;

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("network handler is already running")]
    AlreadyRunning
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

    pub async fn stop(&self) {
        if let Some(handle) = self.task.lock().await.take() {
            if handle.is_finished() {
                if let Err(e) = handle.await {
                    debug!("Network handler was finished with error: {}", e);
                }
            } else {
                handle.abort();
            }
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

    async fn get_versioned_balance_and_topoheight(&self, address: &Address<'_>, asset: &Hash, current_topoheight: Option<u64>) -> Result<Option<(u64, VersionedBalance)>, Error> {
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

                // lets write the final balance
                let mut storage = self.wallet.get_storage().write().await;
                storage.set_balance_for(asset, balance.get_balance())?;

                (res.topoheight, balance)
            }
        };
        Ok(Some((topoheight, balance)))
    }

    async fn get_balance_and_transactions(&self, address: &Address<'_>, asset: &Hash, min_topoheight: u64, mut current_topoheight: Option<u64>) -> Result<(), Error> {
        let mut res = self.get_versioned_balance_and_topoheight(address, asset, current_topoheight).await?;
        while let Some((topoheight, balance)) = res.take() {
            // don't sync already synced blocks
            if min_topoheight > topoheight {
                return Ok(())
            }

            let response = self.api.get_block_with_txs_at_topoheight(topoheight).await?;
            let block: CompleteBlock = response.data.data.into_owned();

            // create Coinbase entry
            if *block.get_miner() == *address.get_public_key() {
                let coinbase = EntryData::Coinbase(response.reward);
                let entry = TransactionEntry::new(response.data.hash.into_owned(), topoheight, None, None, coinbase);
                let mut storage = self.wallet.get_storage().write().await;
                storage.save_transaction(entry.get_hash(), &entry)?;
            }

            let mut latest_nonce_sent = None;
            let (block, txs) = block.split();
            for (tx_hash, tx) in block.get_txs_hashes().iter().zip(txs) {
                let tx = tx.into_owned();
                let is_owner = *tx.get_owner() == *address.get_public_key();
                let fee = if is_owner { Some(tx.get_fee()) } else { None };
                let nonce = if is_owner { Some(tx.get_nonce()) } else { None };
                let (owner, data) = tx.consume();
                let entry: Option<EntryData> = match data {
                    TransactionType::Burn(asset, amount) => {
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
                                let transfer = Transfer::new(tx.to, tx.asset, tx.amount, tx.extra_data);
                                transfers.push(transfer);
                            }
                        }

                        if is_owner {
                            Some(EntryData::Outgoing(transfers))
                        } else {
                            Some(EntryData::Incoming(owner, transfers))
                        }
                    },
                    _ => {
                        error!("Transaction type not supported");
                        None
                    }
                };

                if let Some(entry) = entry {
                    let entry = TransactionEntry::new(tx_hash.clone(), topoheight, fee, nonce, entry);
                    let mut storage = self.wallet.get_storage().write().await;
                    storage.save_transaction(entry.get_hash(), &entry)?;
                }

                if is_owner {
                    latest_nonce_sent = nonce;
                }
            }

            // check that we have a outgoing tx (in case of same wallets used in differents places at same time)
            if let (Some(last_nonce), None) = (latest_nonce_sent, current_topoheight.take()) {
                // don't keep the lock in case of a request
                debug!("Detected a nonce changes for balance at topoheight {}", topoheight);
                let mut storage = self.wallet.get_storage().write().await;
                storage.set_nonce(last_nonce + 1)?;
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
        let mut current_topoheight = {
            // get nonce from chain in case local nonce is not right (chain rewind, TX stuck, TX lost...)
            let nonce = self.api.get_nonce(&address).await.unwrap_or(0);
            let mut storage = self.wallet.get_storage().write().await;
            storage.set_nonce(nonce)?;
            storage.get_daemon_topoheight().unwrap_or(0)
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

            // we are in paused mode, but we can connect again to daemon
            if self.is_paused() {
                info!("Daemon is reachable again, syncing...");
                self.is_paused.store(false, Ordering::SeqCst);
            }

            if info.topoheight == current_topoheight {
                continue;
            }
            debug!("New height detected for chain: {}", info.topoheight);

            if let Err(e) = self.sync_new_blocks(&address, current_topoheight).await {
                error!("Error while syncing new blocks: {}", e);
            }

            // save current topoheight in daemon
            {
                debug!("Saving current topoheight daemon: {}", current_topoheight);
                let mut storage = self.wallet.get_storage().write().await;
                storage.set_daemon_topoheight(current_topoheight)?;
                storage.set_top_block_hash(&info.top_hash)?;
            }
            current_topoheight = info.topoheight;
        }
    }

    async fn sync_new_blocks(&self, address: &Address<'_>, current_topoheight: u64) -> Result<(), Error> {
        // TODO detect new changes in assets
        let mut assets = {
            let storage = self.wallet.get_storage().read().await;
            storage.get_assets()?
        };

        if assets.is_empty() {
            debug!("No assets registered on disk, fetching from chain...");
            assets = self.api.get_assets().await?;
            debug!("Found {} assets", assets.len());
            let mut storage = self.wallet.get_storage().write().await;
            for asset in &assets {
                storage.add_asset(asset)?;
            }
        }

        for asset in assets {
            if let Err(e) = self.get_balance_and_transactions(&address, &asset, current_topoheight, None).await {
                error!("Error while syncing balance for asset {}: {}", asset, e);
            }
        }
        Ok(())
    }
}