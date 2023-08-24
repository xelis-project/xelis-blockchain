use std::{sync::Arc, borrow::Cow};

use anyhow::Context;
use log::info;
use xelis_common::{rpc_server::{RPCHandler, InternalRpcError, parse_params}, config::{VERSION, XELIS_ASSET}, async_handler, api::{wallet::{BuildTransactionParams, FeeBuilder, TransactionResponse, ListTransactionsParams, GetAddressParams, GetBalanceParams, GetTransactionParams}, DataHash, DataElement}, crypto::hash::Hashable};
use serde_json::{Value, json};
use crate::{wallet::{Wallet, WalletError}, entry::{EntryData, TransactionEntry}};

pub fn register_methods(handler: &mut RPCHandler<Arc<Wallet>>) {
    info!("Registering RPC methods...");
    handler.register_method("version", async_handler!(version));
    handler.register_method("get_network", async_handler!(get_network));
    handler.register_method("get_nonce", async_handler!(get_nonce));
    handler.register_method("get_topoheight", async_handler!(get_topoheight));
    handler.register_method("get_address", async_handler!(get_address));
    handler.register_method("get_balance", async_handler!(get_balance));
    handler.register_method("get_tracked_assets", async_handler!(get_tracked_assets));
    handler.register_method("get_transaction", async_handler!(get_transaction));
    handler.register_method("build_transaction", async_handler!(build_transaction));
    handler.register_method("list_transactions", async_handler!(list_transactions));
    handler.register_method("make_integrated_address", async_handler!(make_integrated_address));
}

async fn version(_: Arc<Wallet>, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }
    Ok(json!(VERSION))
}

async fn get_network(wallet: Arc<Wallet>, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }

    let network = wallet.get_network();
    Ok(json!(network))
}

async fn get_nonce(wallet: Arc<Wallet>, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }

    let storage = wallet.get_storage().read().await;
    let nonce = storage.get_nonce()?;
    Ok(json!(nonce))
}

async fn get_topoheight(wallet: Arc<Wallet>, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }

    let storage = wallet.get_storage().read().await;
    let topoheight = storage.get_daemon_topoheight()?;
    Ok(json!(topoheight))
}

async fn get_address(wallet: Arc<Wallet>, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetAddressParams = parse_params(body)?;

    let address = if let Some(data) = params.data {
        wallet.get_address_with(data)
    } else {
        wallet.get_address()
    };

    Ok(json!(address))
}

async fn get_balance(wallet: Arc<Wallet>, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetBalanceParams = parse_params(body)?;
    let asset = params.asset.unwrap_or(XELIS_ASSET);
    let storage = wallet.get_storage().read().await;

    let balance = storage.get_balance_for(&asset)?;
    Ok(json!(balance))
}

async fn get_tracked_assets(wallet: Arc<Wallet>, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }

    let storage = wallet.get_storage().read().await;
    let tracked_assets = storage.get_assets()?;

    Ok(json!(tracked_assets))
}

async fn get_transaction(wallet: Arc<Wallet>, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetTransactionParams = parse_params(body)?;

    let storage = wallet.get_storage().read().await;
    let transaction = storage.get_transaction(&params.hash)?;

    let data: DataHash<'_, TransactionEntry> = DataHash { hash: Cow::Owned(params.hash), data: Cow::Owned(transaction) };
    Ok(json!(data))
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
        inner: DataHash {
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

async fn make_integrated_address(wallet: Arc<Wallet>, body: Value) -> Result<Value, InternalRpcError> {
    let params: DataElement = parse_params(body)?;

    let integrated_address = wallet.get_address_with(params);
    Ok(json!(integrated_address))
}