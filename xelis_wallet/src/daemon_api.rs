use std::borrow::Cow;

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;
use xelis_common::{
    json_rpc::{WebSocketJsonRPCClient, WebSocketJsonRPCClientImpl, JsonRPCResult},
    api::{
        daemon::{
            GetLastBalanceResult, GetBalanceAtTopoHeightParams, GetBalanceParams,
            GetInfoResult, SubmitTransactionParams, BlockResponse,
            GetBlockAtTopoHeightParams, GetTransactionParams, GetNonceParams,
            GetNonceResult, GetAssetsParams, IsTxExecutedInBlockParams
        },
        wallet::NotifyEvent
    },
    account::VersionedBalance,
    crypto::{address::Address, hash::Hash},
    transaction::Transaction,
    serializer::Serializer,
    block::{BlockHeader, Block},
    asset::AssetWithData
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

    pub async fn call<P: Serialize>(&self, method: &String, params: &P) -> JsonRPCResult<Value> {
        self.client.call_with(method.as_str(), params).await
    }

    pub async fn get_version(&self) -> Result<String> {
        let version = self.client.call("get_version").await.context("Error while retrieving version from daemon")?;
        Ok(version)
    }

    pub async fn get_info(&self) -> Result<GetInfoResult> {
        let info = self.client.call("get_info").await.context("Error while retrieving info from chain")?;
        Ok(info)
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

    pub async fn get_last_balance(&self, address: &Address, asset: &Hash) -> Result<GetLastBalanceResult> {
        let balance = self.client.call_with("get_last_balance", &GetBalanceParams {
            address: Cow::Borrowed(address),
            asset: Cow::Borrowed(asset),
        }).await.context("Error while retrieving last balance")?;
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

    pub async fn get_block_at_topoheight(&self, topoheight: u64) -> Result<BlockResponse<'_, BlockHeader>> {
        let block = self.client.call_with("get_block_at_topoheight", &GetBlockAtTopoHeightParams {
            topoheight,
            include_txs: false
        }).await.context(format!("Error while fetching block at topoheight {}", topoheight))?;
        Ok(block)
    }

    pub async fn get_block_with_txs_at_topoheight(&self, topoheight: u64) -> Result<BlockResponse<'_, Block>> {
        let block = self.client.call_with("get_block_at_topoheight", &GetBlockAtTopoHeightParams {
            topoheight,
            include_txs: true
        }).await.context(format!("Error while fetching block at topoheight {}", topoheight))?;
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

    pub async fn get_last_nonce(&self, address: &Address) -> Result<GetNonceResult> {
        let nonce = self.client.call_with("get_nonce", &GetNonceParams {
            address: Cow::Borrowed(address),
            topoheight: None
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
}