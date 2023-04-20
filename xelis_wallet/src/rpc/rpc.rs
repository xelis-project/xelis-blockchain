use std::{sync::Arc, borrow::Cow};

use anyhow::Context;
use log::info;
use xelis_common::{rpc_server::{RPCHandler, InternalRpcError, parse_params}, config::VERSION, async_handler, api::{wallet::{BuildTransactionParams, FeeBuilder, TransactionResponse, ListTransactionsParams}, DataHash}, crypto::hash::Hashable};
use serde_json::{Value, json};
use crate::{wallet::{Wallet, WalletError}, entry::{EntryData, TransactionEntry}};

pub fn register_methods(handler: &mut RPCHandler<Arc<Wallet>>) {
    info!("Registering RPC methods...");
    handler.register_method("version", async_handler!(version));
    handler.register_method("build_transaction", async_handler!(build_transaction));
    handler.register_method("list_transactions", async_handler!(list_transactions));
}

async fn version(_: Arc<Wallet>, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }
    Ok(json!(VERSION))
}

async fn build_transaction(wallet: Arc<Wallet>, body: Value) -> Result<Value, InternalRpcError> {
    let params: BuildTransactionParams = parse_params(body)?;
    // request ask to broadcast the TX but wallet is not connected to any daemon
    if !wallet.is_online().await && params.broadcast {
        return Err(WalletError::NotOnlineMode).context("Cannot broadcast TX")?
    }

    // create the TX
    let storage = wallet.get_storage().read().await;
    let tx = wallet.create_transaction(&storage, params.tx_type, params.fee.unwrap_or(FeeBuilder::Multiplier(1f64)))?;

    // if requested, broadcast the TX ourself
    if params.broadcast {
        wallet.submit_transaction(&tx).await.context("Couldn't broadcast transaction")?;
    }

    // returns the created TX and its hash
    Ok(json!(TransactionResponse {
        tx: DataHash {
            hash: Cow::Owned(tx.hash()),
            data: Cow::Owned(tx)
        }
    }))
}

async fn list_transactions(wallet: Arc<Wallet>, body: Value) -> Result<Value, InternalRpcError> {
    let params: ListTransactionsParams = parse_params(body)?;
    let wallet = wallet.get_storage().read().await;
    let txs = wallet.get_transactions()?;
    let response: Vec<DataHash<'_, TransactionEntry>> = txs.iter().filter(|e| {
        if let Some(topoheight) = &params.min_topoheight {
            if e.get_topoheight() < *topoheight {
                return false
            }
        }

        if let Some(topoheight) = &params.max_topoheight {
            if e.get_topoheight() > *topoheight {
                return false
            }
        }

        match e.get_entry() {
            EntryData::Coinbase(_) if params.accept_coinbase => true,
            EntryData::Burn { .. } if params.accept_burn => true,
            EntryData::Incoming(sender, _) if params.accept_incoming => match &params.address {
                Some(key) => *key == *sender,
                None => true
            },
            EntryData::Outgoing(txs) if params.accept_outgoing => match &params.address {
                Some(filter_key) => txs.iter().find(|tx| {
                    *tx.get_key() == *filter_key
                }).is_some(),
                None => true,
            },
            _ => false
        }
    }).map(|e| {
        let hash = e.get_hash();
        DataHash { hash: Cow::Borrowed(hash), data: Cow::Borrowed(e) }
    }).collect();

    Ok(json!(response))
}