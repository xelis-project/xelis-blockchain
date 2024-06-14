use std::{borrow::Cow, collections::HashSet};

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use xelis_common::{
    tokio::sync::broadcast,
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
        IsAccountRegisteredParams,
        TransactionOrphanedEvent,
        GetTransactionExecutorParams,
        GetTransactionExecutorResult,
        GetStableBalanceResult
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
use log::trace;

pub struct DaemonAPI {
    client: WebSocketJsonRPCClient<NotifyEvent>,
    capacity: usize,
}

impl DaemonAPI {
    pub async fn new(daemon_address: String) -> Result<Self> {
        Self::with_capacity(daemon_address, 64).await
    }

    pub async fn with_capacity(daemon_address: String, capacity: usize) -> Result<Self> {
        let client = WebSocketJsonRPCClientImpl::new(daemon_address).await?;
        Ok(Self {
            client,
            capacity
        })
    }

    // is the websocket connection alive
    pub fn is_online(&self) -> bool {
        trace!("is_online");
        self.client.is_online()
    }

    // Disconnect by closing the connection with node RPC
    pub async fn disconnect(&self) -> Result<()> {
        trace!("disconnect");
        self.client.disconnect().await
    }

    // Try to reconnect using the same client
    pub async fn reconnect(&self) -> Result<bool> {
        trace!("reconnect");
        self.client.reconnect().await
    }

    // On connection event
    pub async fn on_connection(&self) -> broadcast::Receiver<()> {
        trace!("on_connection");
        self.client.on_connection().await
    }

    // On connection lost
    pub async fn on_connection_lost(&self) -> broadcast::Receiver<()> {
        trace!("on_connection_lost");
        self.client.on_connection_lost().await
    }

    pub async fn call<P: Serialize>(&self, method: &String, params: &P) -> JsonRPCResult<Value> {
        trace!("call: {}", method);
        self.client.call_with(method.as_str(), params).await
    }

    pub async fn on_new_block_event(&self) -> Result<EventReceiver<NewBlockEvent>> {
        trace!("on_new_block_event");
        let receiver = self.client.subscribe_event(NotifyEvent::NewBlock, self.capacity).await?;
        Ok(receiver)
    }

    pub async fn on_block_ordered_event(&self) -> Result<EventReceiver<BlockOrderedEvent>> {
        trace!("on_block_ordered_event");
        let receiver = self.client.subscribe_event(NotifyEvent::BlockOrdered, self.capacity).await?;
        Ok(receiver)
    }

    pub async fn on_transaction_orphaned_event(&self) -> Result<EventReceiver<TransactionOrphanedEvent>> {
        trace!("on_transaction_orphaned_event");
        let receiver = self.client.subscribe_event(NotifyEvent::TransactionOrphaned, self.capacity).await?;
        Ok(receiver)
    }

    pub async fn on_stable_height_changed_event(&self) -> Result<EventReceiver<StableHeightChangedEvent>> {
        trace!("on_stable_height_changed_event");
        let receiver = self.client.subscribe_event(NotifyEvent::StableHeightChanged, self.capacity).await?;
        Ok(receiver)
    }

    pub async fn on_transaction_added_in_mempool_event(&self) -> Result<EventReceiver<TransactionAddedInMempoolEvent>> {
        trace!("on_transaction_added_in_mempool_event");
        let receiver = self.client.subscribe_event(NotifyEvent::TransactionAddedInMempool, self.capacity).await?;
        Ok(receiver)
    }

    pub async fn get_version(&self) -> Result<String> {
        trace!("get_version");
        let version = self.client.call("get_version").await?;
        Ok(version)
    }

    pub async fn get_info(&self) -> Result<GetInfoResult> {
        trace!("get_info");
        let info = self.client.call("get_info").await?;
        Ok(info)
    }

    pub async fn get_asset(&self, asset: &Hash) -> Result<AssetData> {
        trace!("get_asset");
        let assets = self.client.call_with("get_asset", &GetAssetParams {
            asset: Cow::Borrowed(asset)
        }).await?;
        Ok(assets)
    }

    pub async fn get_account_assets(&self, address: &Address) -> Result<HashSet<Hash>> {
        trace!("get_account_assets");
        let assets = self.client.call_with("get_account_assets", &GetAccountAssetsParams {
            address: Cow::Borrowed(address)
        }).await?;
        Ok(assets)
    }

    pub async fn count_assets(&self) -> Result<usize> {
        trace!("count_assets");
        let count = self.client.call("count_assets").await?;
        Ok(count)
    }

    pub async fn get_assets(&self, skip: Option<usize>, maximum: Option<usize>, minimum_topoheight: Option<u64>, maximum_topoheight: Option<u64>) -> Result<Vec<AssetWithData>> {
        trace!("get_assets");
        let assets = self.client.call_with("get_assets", &GetAssetsParams {
            maximum,
            skip,
            minimum_topoheight,
            maximum_topoheight
        }).await?;
        Ok(assets)
    }

    pub async fn get_balance(&self, address: &Address, asset: &Hash) -> Result<GetBalanceResult> {
        trace!("get_balance");
        let balance = self.client.call_with("get_balance", &GetBalanceParams {
            address: Cow::Borrowed(address),
            asset: Cow::Borrowed(asset),
        }).await?;
        Ok(balance)
    }

    pub async fn get_balance_at_topoheight(&self, address: &Address, asset: &Hash, topoheight: u64) -> Result<VersionedBalance> {
        trace!("get_balance_at_topoheight");
        let balance = self.client.call_with("get_balance_at_topoheight", &GetBalanceAtTopoHeightParams {
            topoheight,
            asset: Cow::Borrowed(asset),
            address: Cow::Borrowed(address)
        }).await?;
        Ok(balance)
    }

    pub async fn get_block_at_topoheight(&self, topoheight: u64) -> Result<BlockResponse> {
        trace!("get_block_at_topoheight");
        let block = self.client.call_with("get_block_at_topoheight", &GetBlockAtTopoHeightParams {
            topoheight,
            include_txs: false
        }).await?;
        Ok(block)
    }

    pub async fn get_block_with_txs_at_topoheight(&self, topoheight: u64) -> Result<BlockResponse> {
        trace!("get_block_with_txs_at_topoheight");
        let block = self.client.call_with("get_block_at_topoheight", &GetBlockAtTopoHeightParams {
            topoheight,
            include_txs: true
        }).await?;
        Ok(block)
    }

    pub async fn get_transaction(&self, hash: &Hash) -> Result<Transaction> {
        trace!("get_transaction");
        let tx = self.client.call_with("get_transaction", &GetTransactionParams {
            hash: Cow::Borrowed(hash)
        }).await?;
        Ok(tx)
    }

    pub async fn get_transaction_executor(&self, hash: &Hash) -> Result<GetTransactionExecutorResult> {
        trace!("get_transaction_executor");
        let executor = self.client.call_with("get_transaction_executor", &GetTransactionExecutorParams {
            hash: Cow::Borrowed(hash)
        }).await?;
        Ok(executor)
    }

    pub async fn submit_transaction(&self, transaction: &Transaction) -> Result<()> {
        trace!("submit_transaction");
        let _: bool = self.client.call_with("submit_transaction", &SubmitTransactionParams {
            data: transaction.to_hex()
        }).await?;
        Ok(())
    }

    pub async fn get_nonce(&self, address: &Address) -> Result<GetNonceResult> {
        trace!("get_nonce");
        let nonce = self.client.call_with("get_nonce", &GetNonceParams {
            address: Cow::Borrowed(address)
        }).await?;
        Ok(nonce)
    }

    pub async fn is_tx_executed_in_block(&self, tx_hash: &Hash, block_hash: &Hash) -> Result<bool> {
        trace!("is_tx_executed_in_block");
        let is_executed = self.client.call_with("is_tx_executed_in_block", &IsTxExecutedInBlockParams {
            tx_hash: Cow::Borrowed(tx_hash),
            block_hash: Cow::Borrowed(block_hash)
        }).await?;
        Ok(is_executed)
    }

    pub async fn get_mempool_cache(&self, address: &Address) -> Result<GetMempoolCacheResult> {
        trace!("get_mempool_cache");
        let cache = self.client.call_with("get_mempool_cache", &GetMempoolCacheParams {
            address: Cow::Borrowed(address)
        }).await?;
        Ok(cache)
    }

    pub async fn is_account_registered(&self, address: &Address, in_stable_height: bool) -> Result<bool> {
        trace!("is_account_registered");
        let is_registered = self.client.call_with("is_account_registered", &IsAccountRegisteredParams {
            address: Cow::Borrowed(address),
            in_stable_height,
        }).await?;
        Ok(is_registered)
    }

    pub async fn get_stable_topoheight(&self) -> Result<u64> {
        trace!("get_stable_topoheight");
        let topoheight = self.client.call("get_stable_topoheight").await?;
        Ok(topoheight)
    }

    pub async fn get_stable_balance(&self, address: &Address, asset: &Hash) -> Result<GetStableBalanceResult> {
        trace!("get_stable_balance");
        let balance = self.client.call_with("get_stable_balance", &GetBalanceParams {
            address: Cow::Borrowed(address),
            asset: Cow::Borrowed(asset),
        }).await?;
        Ok(balance)
    }
}