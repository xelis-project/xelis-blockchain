use std::{borrow::Cow, collections::HashSet};

use anyhow::{Context, Result};
use xelis_common::{json_rpc::JsonRPCClient, api::daemon::{GetLastBalanceResult, GetBalanceAtTopoHeightParams, GetBalanceParams, GetInfoResult, SubmitTransactionParams, BlockResponse, GetBlockAtTopoHeightParams, GetTransactionParams, GetNonceParams}, account::VersionedBalance, crypto::{address::Address, hash::Hash}, transaction::Transaction, serializer::Serializer, block::Block};

pub struct DaemonAPI {
    client: JsonRPCClient,
}

impl DaemonAPI {
    pub fn new(daemon_address: String) -> Self {
        Self {
            client: JsonRPCClient::new(daemon_address)
        }
    }

    pub async fn get_version(&self) -> Result<String> {
        let version = self.client.call("get_version").await.context("Error while retrieving version from daemon")?;
        Ok(version)
    }

    pub async fn get_info(&self) -> Result<GetInfoResult> {
        let info = self.client.call("get_info").await.context("Error while retrieving info from chain")?;
        Ok(info)
    }

    pub async fn get_assets(&self) -> Result<HashSet<Hash>> {
        let info = self.client.call("get_assets").await.context("Error while retrieving assets registered")?;
        Ok(info)
    }

    pub async fn get_last_balance(&self, address: &Address<'_>, asset: &Hash) -> Result<GetLastBalanceResult> {
        let balance = self.client.call_with("get_last_balance", &GetBalanceParams {
            address: Cow::Borrowed(address),
            asset: Cow::Borrowed(asset),
        }).await.context("Error while retrieving last balance")?;
        Ok(balance)
    }

    pub async fn get_balance_at_topoheight(&self, address: &Address<'_>, asset: &Hash, topoheight: u64) -> Result<VersionedBalance> {
        let balance = self.client.call_with("get_balance_at_topoheight", &GetBalanceAtTopoHeightParams {
            topoheight,
            asset: Cow::Borrowed(asset),
            address: Cow::Borrowed(address)
        }).await.context("Error while retrieving balance at topoheight")?;
        Ok(balance)
    }

    pub async fn get_block_at_topoheight(&self, topoheight: u64) -> Result<BlockResponse<'_, Block>> {
        let block = self.client.call_with("get_block_at_topoheight", &GetBlockAtTopoHeightParams {
            topoheight
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
        let _ = self.client.call_with("submit_transaction", &SubmitTransactionParams {
            data: transaction.to_hex()
        }).await.context("Error while sending transaction")?;
        Ok(())
    }

    pub async fn get_nonce(&self, address: &Address<'_>) -> Result<u64> {
        let nonce = self.client.call_with("get_nonce", &GetNonceParams {
            address: Cow::Borrowed(address)
        }).await.context(format!("Error while fetching nonce from address {}", address))?;
        Ok(nonce)
    }
}