use std::{borrow::Cow, collections::HashSet};

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::broadcast;
use xelis_common::{
    json_rpc::{
        WebSocketJsonRPCClient,
        WebSocketJsonRPCClientImpl,
        JsonRPCResult,
        EventReceiver
    },
    api::daemon::{
        GetBalanceResult,
        GetBalanceAtTopoHeightParams,
        GetBalanceParams,
        GetInfoResult,
        SubmitTransactionParams,
        BlockResponse,
        GetBlockAtTopoHeightParams,
        GetTransactionParams,
        GetNonceParams,
        GetNonceResult,
        GetAssetsParams,
        IsTxExecutedInBlockParams,
        NotifyEvent,
        NewBlockEvent,
        BlockOrderedEvent,
        StableHeightChangedEvent,
        TransactionAddedInMempoolEvent,
        GetAccountAssetsParams,
        GetAssetParams,
        GetMempoolCacheParams,
        GetMempoolCacheResult,
        IsAccountRegisteredParams
    },
    account::VersionedBalance,
    crypto::{
        Address,
        Hash
    },
    transaction::Transaction,
    serializer::Serializer,
    asset::{
        AssetWithData,
        AssetData
    }
};

pub struct DaemonAPI {
    client: WebSocketJsonRPCClient<NotifyEvent>,
}

impl DaemonAPI {
    pub async fn new(daemon_address: String) -> Result<Self> {
        let client = WebSocketJsonRPCClientImpl::new(daemon_address).await?;
        Ok(Self {
            client
        })
    }

    // is the websocket connection alive
    pub fn is_online(&self) -> bool {
        self.client.is_online()
    }

    // Disconnect by closing the connection with node RPC
    pub async fn disconnect(&self) -> Result<()> {
        self.client.disconnect().await
    }

    // Try to reconnect using the same client
    pub async fn reconnect(&self) -> Result<bool> {
        self.client.reconnect().await
    }

    // On connection event
    pub async fn on_connection(&self) -> broadcast::Receiver<()> {
        self.client.on_connection().await
    }

    // On connection lost
    pub async fn on_connection_lost(&self) -> broadcast::Receiver<()> {
        self.client.on_connection_lost().await
    }

    pub async fn call<P: Serialize>(&self, method: &String, params: &P) -> JsonRPCResult<Value> {
        self.client.call_with(method.as_str(), params).await
    }

    pub async fn on_new_block_event(&self) -> Result<EventReceiver<NewBlockEvent>> {
        let receiver = self.client.subscribe_event(NotifyEvent::NewBlock).await?;
        Ok(receiver)
    }

    pub async fn on_block_ordered_event(&self) -> Result<EventReceiver<BlockOrderedEvent>> {
        let receiver = self.client.subscribe_event(NotifyEvent::BlockOrdered).await?;
        Ok(receiver)
    }

    pub async fn on_stable_height_changed_event(&self) -> Result<EventReceiver<StableHeightChangedEvent>> {
        let receiver = self.client.subscribe_event(NotifyEvent::StableHeightChanged).await?;
        Ok(receiver)
    }

    pub async fn on_transaction_added_in_mempool_event(&self) -> Result<EventReceiver<TransactionAddedInMempoolEvent>> {
        let receiver = self.client.subscribe_event(NotifyEvent::TransactionAddedInMempool).await?;
        Ok(receiver)
    }

    pub async fn get_version(&self) -> Result<String> {
        let version = self.client.call("get_version").await.context("Error while retrieving version from daemon")?;
        Ok(version)
    }

    pub async fn get_info(&self) -> Result<GetInfoResult> {
        let info = self.client.call("get_info").await.context("Error while retrieving info from chain")?;
        Ok(info)
    }

    pub async fn get_asset(&self, asset: &Hash) -> Result<AssetData> {
        let assets = self.client.call_with("get_asset", &GetAssetParams {
            asset: Cow::Borrowed(asset)
        }).await.context("Error while retrieving asset data")?;
        Ok(assets)
    }

    pub async fn get_account_assets(&self, address: &Address) -> Result<HashSet<Hash>> {
        let assets = self.client.call_with("get_account_assets", &GetAccountAssetsParams {
            address: Cow::Borrowed(address)
        }).await.context("Error while retrieving account assets")?;
        Ok(assets)
    }

    pub async fn count_assets(&self) -> Result<usize> {
        let count = self.client.call("count_assets").await?;
        Ok(count)
    }

    pub async fn get_assets(&self, skip: Option<usize>, maximum: Option<usize>, minimum_topoheight: Option<u64>, maximum_topoheight: Option<u64>) -> Result<Vec<AssetWithData>> {
        let assets = self.client.call_with("get_assets", &GetAssetsParams {
            maximum,
            skip,
            minimum_topoheight,
            maximum_topoheight
        }).await?;
        Ok(assets)
    }

    pub async fn get_balance(&self, address: &Address, asset: &Hash) -> Result<GetBalanceResult> {
        let balance = self.client.call_with("get_balance", &GetBalanceParams {
            address: Cow::Borrowed(address),
            asset: Cow::Borrowed(asset),
        }).await.context("Error while retrieving balance")?;
        Ok(balance)
    }

    pub async fn get_balance_at_topoheight(&self, address: &Address, asset: &Hash, topoheight: u64) -> Result<VersionedBalance> {
        let balance = self.client.call_with("get_balance_at_topoheight", &GetBalanceAtTopoHeightParams {
            topoheight,
            asset: Cow::Borrowed(asset),
            address: Cow::Borrowed(address)
        }).await.context("Error while retrieving balance at topoheight")?;
        Ok(balance)
    }

    pub async fn get_block_at_topoheight(&self, topoheight: u64) -> Result<BlockResponse> {
        let block = self.client.call_with("get_block_at_topoheight", &GetBlockAtTopoHeightParams {
            topoheight,
            include_txs: false
        }).await.context(format!("Error while fetching block at topoheight {}", topoheight))?;
        Ok(block)
    }

    pub async fn get_block_with_txs_at_topoheight(&self, topoheight: u64) -> Result<BlockResponse> {
        let block = self.client.call_with("get_block_at_topoheight", &GetBlockAtTopoHeightParams {
            topoheight,
            include_txs: true
        }).await.context(format!("Error while fetching block with txs at topoheight {}", topoheight))?;
        Ok(block)
    }

    pub async fn get_transaction(&self, hash: &Hash) -> Result<Transaction> {
        let tx = self.client.call_with("get_transaction", &GetTransactionParams {
            hash: Cow::Borrowed(hash)
        }).await.context(format!("Error while fetching transaction {}", hash))?;
        Ok(tx)
    }

    pub async fn submit_transaction(&self, transaction: &Transaction) -> Result<()> {
        let _: bool = self.client.call_with("submit_transaction", &SubmitTransactionParams {
            data: transaction.to_hex()
        }).await?;
        Ok(())
    }

    pub async fn get_nonce(&self, address: &Address) -> Result<GetNonceResult> {
        let nonce = self.client.call_with("get_nonce", &GetNonceParams {
            address: Cow::Borrowed(address)
        }).await.context(format!("Error while fetching nonce from address {}", address))?;
        Ok(nonce)
    }

    pub async fn is_tx_executed_in_block(&self, tx_hash: &Hash, block_hash: &Hash) -> Result<bool> {
        let is_executed = self.client.call_with("is_tx_executed_in_block", &IsTxExecutedInBlockParams {
            tx_hash: Cow::Borrowed(tx_hash),
            block_hash: Cow::Borrowed(block_hash)
        }).await.context(format!("Error while checking if tx {} is executed in block {}", tx_hash, block_hash))?;
        Ok(is_executed)
    }

    pub async fn get_mempool_cache(&self, address: &Address) -> Result<GetMempoolCacheResult> {
        let cache = self.client.call_with("get_mempool_cache", &GetMempoolCacheParams {
            address: Cow::Borrowed(address)
        }).await.context("Error while fetching mempool cache")?;
        Ok(cache)
    }

    pub async fn is_account_registered(&self, address: &Address, in_stable_height: bool) -> Result<bool> {
        let is_registered = self.client.call_with("is_account_registered", &IsAccountRegisteredParams {
            address: Cow::Borrowed(address),
            in_stable_height,
        }).await.context("Error while checking if account is registered")?;
        Ok(is_registered)
    }
}