use std::{sync::Arc, borrow::Cow};

use anyhow::Context;
use log::info;
use xelis_common::{rpc_server::{RPCHandler, InternalRpcError, parse_params}, config::{VERSION, XELIS_ASSET}, async_handler, api::{wallet::{BuildTransactionParams, FeeBuilder, TransactionResponse, ListTransactionsParams, GetAddressParams, GetBalanceParams, GetTransactionParams, SplitAddressParams, SplitAddressResult, GetCustomDataParams, SetCustomDataParams, GetCustomTreeKeysParams}, DataHash, DataElement, DataValue}, crypto::{hash::Hashable, address::AddressType}};
use serde_json::{Value, json};
use crate::{wallet::{Wallet, WalletError}, entry::TransactionEntry};

pub fn register_methods(handler: &mut RPCHandler<Arc<Wallet>>) {
    info!("Registering RPC methods...");
    handler.register_method("get_version", async_handler!(get_version));
    handler.register_method("get_network", async_handler!(get_network));
    handler.register_method("get_nonce", async_handler!(get_nonce));
    handler.register_method("get_topoheight", async_handler!(get_topoheight));
    handler.register_method("get_address", async_handler!(get_address));
    handler.register_method("split_address", async_handler!(split_address));
    handler.register_method("get_balance", async_handler!(get_balance));
    handler.register_method("get_tracked_assets", async_handler!(get_tracked_assets));
    handler.register_method("get_transaction", async_handler!(get_transaction));
    handler.register_method("build_transaction", async_handler!(build_transaction));
    handler.register_method("list_transactions", async_handler!(list_transactions));
    handler.register_method("get_custom_tree_keys_from_db", async_handler!(get_custom_tree_keys_from_db));
    handler.register_method("get_custom_data_from_db", async_handler!(get_custom_data_from_db));
    handler.register_method("set_custom_data_in_db", async_handler!(set_custom_data_in_db));
}

async fn get_version(_: Arc<Wallet>, body: Value) -> Result<Value, InternalRpcError> {
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

    let address = if let Some(data) = params.integrated_data {
        wallet.get_address_with(data)
    } else {
        wallet.get_address()
    };

    Ok(json!(address))
}

async fn split_address(_: Arc<Wallet>, body: Value) -> Result<Value, InternalRpcError> {
    let params: SplitAddressParams<'_> = parse_params(body)?;
    let address = params.address;

    let (address, addr_type) = address.split();
    let integrated_data = match addr_type {
        AddressType::Data(data) => data,
        AddressType::Normal => return Err(InternalRpcError::CustomStr("Address is not an integrated address"))
    };

    Ok(json!(SplitAddressResult {
        address,
        integrated_data
    }))
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
    let storage = wallet.get_storage().read().await;
    let txs = storage.get_filtered_transactions(params.address.as_ref(), params.min_topoheight, params.max_topoheight, params.accept_incoming, params.accept_outgoing, params.accept_coinbase, params.accept_burn, params.query.as_ref())?;
    Ok(json!(txs))
}

async fn get_custom_tree_keys_from_db(wallet: Arc<Wallet>, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetCustomTreeKeysParams = parse_params(body)?;
    let storage = wallet.get_storage().read().await;
    let keys: Vec<DataValue> = storage.get_custom_tree_keys(&params.tree)?;

    Ok(json!(keys))
}

async fn get_custom_data_from_db(wallet: Arc<Wallet>, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetCustomDataParams = parse_params(body)?;
    let storage = wallet.get_storage().read().await;
    let value: DataElement = storage.get_custom_data(&params.tree, &params.key)?;

    Ok(json!(value))
}

async fn set_custom_data_in_db(wallet: Arc<Wallet>, body: Value) -> Result<Value, InternalRpcError> {
    let params: SetCustomDataParams = parse_params(body)?;
    let storage = wallet.get_storage().read().await;
    let value: DataElement = storage.get_custom_data(&params.tree, &params.key)?;

    Ok(json!(value))
}