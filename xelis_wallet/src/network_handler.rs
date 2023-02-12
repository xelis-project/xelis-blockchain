use std::{fmt::Display, sync::Arc};

use thiserror::Error;
use anyhow::Error;
use log::debug;
use tokio::{task::JoinHandle, sync::Mutex};

use crate::{api::DaemonAPI, wallet::Wallet};

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
    api: DaemonAPI
}

impl NetworkHandler {
    pub async fn new<S: Display>(wallet: Arc<Wallet>, daemon_address: S) -> Result<SharedNetworkHandler, Error> {
        let api = DaemonAPI::new(format!("{}/json_rpc", daemon_address));
        // check that we can correctly get version from daemon
        let version = api.get_version().await?;
        debug!("Connected to daemon running version {}", version);

        Ok(Arc::new(Self {
            task: Mutex::new(None),
            wallet,
            api
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

    // check if the network handler is running (that we have a task and its not finished)
    pub async fn is_running(&self) -> bool {
        let task = self.task.lock().await;
        if let Some(handle) = task.as_ref() {
            !handle.is_finished()
        } else {
            false
        }
    }

    async fn start_syncing(self: Arc<Self>) -> Result<(), Error> {
        // get infos from chain
        // TODO compare them with already stored to not resync fully each time
        let info = self.api.get_info().await?;
        //self.storage.set_topoheight(info.topoheight)?;
        //self.storage.set_top_block_hash(&info.top_hash)?;

        let address = self.wallet.get_address();
        let assets = self.api.get_assets().await?;
        for asset in &assets {
            debug!("Checking balance for asset {}", asset);
            let result = self.api.get_last_balance(&address, asset).await?;
            let mut balance = result.balance;
            debug!("Balance: {}", balance.get_balance());
    
            // save current balance
            //self.storage.set_balance_for(asset, balance.get_balance())?;

            while let Some(previous_topo) = balance.get_previous_topoheight() {
                balance = self.api.get_balance_at_topoheight(&address, asset, previous_topo).await?;
                debug!("Detected balance change for {} at topoheight {}", asset, previous_topo);
            }    
        }

        Ok(())
    }
}