use std::{sync::Arc, borrow::Cow};

use anyhow::Context as AnyContext;
use log::info;
use xelis_common::{rpc_server::{RPCHandler, InternalRpcError, parse_params, Context, websocket::WebSocketSessionShared}, config::{VERSION, XELIS_ASSET}, async_handler, api::{wallet::{BuildTransactionParams, FeeBuilder, TransactionResponse, ListTransactionsParams, GetAddressParams, GetBalanceParams, GetTransactionParams, SplitAddressParams, SplitAddressResult, GetCustomDataParams, SetCustomDataParams, GetCustomTreeKeysParams, GetAssetPrecisionParams, RescanParams}, DataHash, DataElement, DataValue}, crypto::hash::Hashable, serializer::Serializer};
use serde_json::{Value, json};
use crate::{wallet::{Wallet, WalletError}, entry::TransactionEntry};

use super::xswd::XSWDWebSocketHandler;

pub fn register_methods(handler: &mut RPCHandler<Arc<Wallet>>) {
    info!("Registering RPC methods...");
    handler.register_method("get_version", async_handler!(get_version));
    handler.register_method("get_network", async_handler!(get_network));
    handler.register_method("get_nonce", async_handler!(get_nonce));
    handler.register_method("get_topoheight", async_handler!(get_topoheight));
    handler.register_method("get_address", async_handler!(get_address));
    handler.register_method("split_address", async_handler!(split_address));
    handler.register_method("rescan", async_handler!(rescan));
    handler.register_method("get_balance", async_handler!(get_balance));
    handler.register_method("get_tracked_assets", async_handler!(get_tracked_assets));
    handler.register_method("get_asset_precision", async_handler!(get_asset_precision));
    handler.register_method("get_transaction", async_handler!(get_transaction));
    handler.register_method("build_transaction", async_handler!(build_transaction));
    handler.register_method("list_transactions", async_handler!(list_transactions));
    handler.register_method("is_online", async_handler!(is_online));
    
    // These functions are restricted to XSWD only
    handler.register_method("get_custom_tree_keys_from_db", async_handler!(get_custom_tree_keys_from_db));
    handler.register_method("get_custom_data_from_db", async_handler!(get_custom_data_from_db));
    handler.register_method("set_custom_data_in_db", async_handler!(set_custom_data_in_db));
}

async fn get_version(_: Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }
    Ok(json!(VERSION))
}

async fn get_network(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }

    let wallet: &Arc<Wallet> = context.get()?;
    let network = wallet.get_network();
    Ok(json!(network))
}

async fn get_nonce(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }

    let wallet: &Arc<Wallet> = context.get()?;
    let storage = wallet.get_storage().read().await;
    let nonce = storage.get_nonce()?;
    Ok(json!(nonce))
}

async fn get_topoheight(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }

    let wallet: &Arc<Wallet> = context.get()?;
    let storage = wallet.get_storage().read().await;
    let topoheight = storage.get_daemon_topoheight()?;
    Ok(json!(topoheight))
}

async fn get_address(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetAddressParams = parse_params(body)?;

    let wallet: &Arc<Wallet> = context.get()?;
    let address = if let Some(data) = params.integrated_data {
        wallet.get_address_with(data)
    } else {
        wallet.get_address()
    };

    Ok(json!(address))
}

async fn split_address(_: Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: SplitAddressParams = parse_params(body)?;
    let address = params.address;

    let (data, address) = address.extract_data();
    let integrated_data = data.ok_or(InternalRpcError::CustomStr("Address is not an integrated address"))?;

    Ok(json!(SplitAddressResult {
        address,
        integrated_data
    }))
}

async fn rescan(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: RescanParams = parse_params(body)?;
    let wallet: &Arc<Wallet> = context.get()?;
    wallet.rescan(params.until_topoheight.unwrap_or(0)).await.context("Error while rescanning wallet")?;
    Ok(json!(true))
}

async fn get_balance(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetBalanceParams = parse_params(body)?;
    let asset = params.asset.unwrap_or(XELIS_ASSET);
    let wallet: &Arc<Wallet> = context.get()?;
    let storage = wallet.get_storage().read().await;

    let balance = storage.get_balance_for(&asset)?;
    Ok(json!(balance))
}

async fn get_tracked_assets(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }

    let wallet: &Arc<Wallet> = context.get()?;
    let storage = wallet.get_storage().read().await;
    let tracked_assets = storage.get_assets()?;

    Ok(json!(tracked_assets))
}

async fn get_asset_precision(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetAssetPrecisionParams = parse_params(body)?;

    let wallet: &Arc<Wallet> = context.get()?;
    let storage = wallet.get_storage().read().await;
    let precision = storage.get_asset_decimals(&params.asset)?;
    Ok(json!(precision))
}

async fn get_transaction(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetTransactionParams = parse_params(body)?;

    let wallet: &Arc<Wallet> = context.get()?;
    let storage = wallet.get_storage().read().await;
    let transaction = storage.get_transaction(&params.hash)?;

    let data: DataHash<'_, TransactionEntry> = DataHash { hash: Cow::Owned(params.hash), data: Cow::Owned(transaction) };
    Ok(json!(data))
}

async fn build_transaction(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: BuildTransactionParams = parse_params(body)?;
    let wallet: &Arc<Wallet> = context.get()?;
    // request ask to broadcast the TX but wallet is not connected to any daemon
    if !wallet.is_online().await && params.broadcast {
        return Err(WalletError::NotOnlineMode).context("Cannot broadcast TX")?
    }

    // create the TX
    let tx = {
        let storage = wallet.get_storage().read().await;
        wallet.create_transaction(&storage, params.tx_type, params.fee.unwrap_or(FeeBuilder::Multiplier(1f64)))?
    };

    // if requested, broadcast the TX ourself
    if params.broadcast {
        wallet.submit_transaction(&tx).await.context("Couldn't broadcast transaction")?;
    }

    // returns the created TX and its hash
    Ok(json!(TransactionResponse {
        tx_as_hex: if params.tx_as_hex {
            Some(hex::encode(tx.to_bytes()))
        } else {
            None
        },
        inner: DataHash {
            hash: Cow::Owned(tx.hash()),
            data: Cow::Owned(tx)
        }
    }))
}

async fn list_transactions(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: ListTransactionsParams = parse_params(body)?;
    if let Some(addr) = &params.address {
        if !addr.is_normal() {
            return Err(InternalRpcError::CustomStr("Address should be in normal format (not integrated address)"))
        }
    }

    let wallet: &Arc<Wallet> = context.get()?;
    let storage = wallet.get_storage().read().await;
    let opt_key = params.address.map(|addr| addr.to_public_key());
    let txs = storage.get_filtered_transactions(opt_key.as_ref(), params.min_topoheight, params.max_topoheight, params.accept_incoming, params.accept_outgoing, params.accept_coinbase, params.accept_burn, params.query.as_ref())?;
    Ok(json!(txs))
}

async fn is_online(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }

    let wallet: &Arc<Wallet> = context.get()?;
    let is_connected = wallet.is_online().await;
    Ok(json!(is_connected))
}

async fn get_tree_name(context: &Context, tree: String) -> Result<String, InternalRpcError> {
    // If the API is not used through XSWD, we don't need to prefix the tree name with the app id
    if context.has::<&WebSocketSessionShared<XSWDWebSocketHandler<Arc<Wallet>>>>() {
        return Ok(tree)
    }

    // Retrieve the app data to get its id and to have section of trees between differents dApps
    let session: &WebSocketSessionShared<XSWDWebSocketHandler<Arc<Wallet>>> = context.get()?;
    let xswd = session.get_server().get_handler();
    let applications = xswd.get_applications().read().await;
    let app = applications.get(session).ok_or_else(|| InternalRpcError::InvalidContext)?;

    Ok(format!("{}-{}", app.get_id(), tree))
}

async fn get_custom_tree_keys_from_db(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetCustomTreeKeysParams = parse_params(body)?;
    let wallet: &Arc<Wallet> = context.get()?;
    let tree = get_tree_name(&context, params.tree).await?;
    let storage = wallet.get_storage().read().await;
    let keys: Vec<DataValue> = storage.get_custom_tree_keys(&tree)?;

    Ok(json!(keys))
}

async fn get_custom_data_from_db(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetCustomDataParams = parse_params(body)?;
    let wallet: &Arc<Wallet> = context.get()?;
    let tree = get_tree_name(&context, params.tree).await?;

    let storage = wallet.get_storage().read().await;
    let value: DataElement = storage.get_custom_data(&tree, &params.key)?;

    Ok(json!(value))
}

async fn set_custom_data_in_db(context: Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: SetCustomDataParams = parse_params(body)?;
    let wallet: &Arc<Wallet> = context.get()?;
    let tree = get_tree_name(&context, params.tree).await?;
    let storage = wallet.get_storage().read().await;
    let value: DataElement = storage.get_custom_data(&tree, &params.key)?;

    Ok(json!(value))
}