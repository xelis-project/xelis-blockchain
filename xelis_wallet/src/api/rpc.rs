use std::{sync::Arc, borrow::Cow};
use anyhow::Context as AnyContext;
use xelis_common::{
    api::{
        wallet::{
            BuildTransactionParams,
            BuildTransactionOfflineParams,
            DeleteParams,
            EstimateFeesParams,
            GetAddressParams,
            GetAssetPrecisionParams,
            GetBalanceParams,
            GetMatchingKeysParams,
            CountMatchingEntriesParams,
            GetTransactionParams,
            GetValueFromKeyParams,
            HasKeyParams,
            ListTransactionsParams,
            QueryDBParams,
            RescanParams,
            StoreParams,
            TransactionResponse,
            SetOnlineModeParams,
            EstimateExtraDataSizeParams,
            EstimateExtraDataSizeResult,
            NetworkInfoResult
        },
        SplitAddressParams,
        SplitAddressResult,
        DataElement,
        DataHash
    },
    async_handler,
    config::{VERSION, XELIS_ASSET},
    context::Context,
    crypto::Hashable,
    rpc_server::{
        parse_params,
        websocket::WebSocketSessionShared,
        InternalRpcError,
        RPCHandler
    },
    serializer::Serializer,
    transaction::extra_data::ExtraData,
};
use serde_json::{Value, json};
use crate::{
    error::WalletError,
    storage::Balance,
    transaction_builder::TransactionBuilderState,
    wallet::Wallet
};
use super::xswd::XSWDWebSocketHandler;
use log::{info, warn};

// Register all RPC methods
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
    handler.register_method("has_balance", async_handler!(has_balance));
    handler.register_method("get_tracked_assets", async_handler!(get_tracked_assets));
    handler.register_method("get_asset_precision", async_handler!(get_asset_precision));
    handler.register_method("get_transaction", async_handler!(get_transaction));
    handler.register_method("build_transaction", async_handler!(build_transaction));
    handler.register_method("build_transaction_offline", async_handler!(build_transaction_offline));
    handler.register_method("clear_tx_cache", async_handler!(clear_tx_cache));
    handler.register_method("list_transactions", async_handler!(list_transactions));
    handler.register_method("is_online", async_handler!(is_online));
    handler.register_method("set_online_mode", async_handler!(set_online_mode));
    handler.register_method("set_offline_mode", async_handler!(set_offline_mode));
    handler.register_method("sign_data", async_handler!(sign_data));
    handler.register_method("estimate_fees", async_handler!(estimate_fees));
    handler.register_method("estimate_extra_data_size", async_handler!(estimate_extra_data_size));
    handler.register_method("network_info", async_handler!(network_info));

    // These functions allow to have an encrypted DB directly in the wallet storage
    // You can retrieve keys, values, have differents trees, and store values
    // It is restricted in XSWD context (each app access to their own trees), and open to everything in RPC
    // Keys and values can be anything
    handler.register_method("get_matching_keys", async_handler!(get_matching_keys));
    handler.register_method("count_matching_entries", async_handler!(count_matching_entries));
    handler.register_method("get_value_from_key", async_handler!(get_value_from_key));
    handler.register_method("store", async_handler!(store));
    handler.register_method("delete", async_handler!(delete));
    handler.register_method("delete_tree_entries", async_handler!(delete_tree_entries));
    handler.register_method("has_key", async_handler!(has_key));
    handler.register_method("query_db", async_handler!(query_db));
}

// Retrieve the version of the wallet
async fn get_version(_: &Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }
    Ok(json!(VERSION))
}

// Retrieve the network of the wallet
async fn get_network(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }

    let wallet: &Arc<Wallet> = context.get()?;
    let network = wallet.get_network();
    Ok(json!(network))
}

// Retrieve the current nonce of the wallet
async fn get_nonce(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }

    let wallet: &Arc<Wallet> = context.get()?;
    let storage = wallet.get_storage().read().await;
    let nonce = storage.get_nonce()?;
    Ok(json!(nonce))
}

// Retrieve the current topoheight until which the wallet is synced
async fn get_topoheight(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }

    let wallet: &Arc<Wallet> = context.get()?;
    let storage = wallet.get_storage().read().await;
    let topoheight = storage.get_synced_topoheight()?;
    Ok(json!(topoheight))
}

// Retrieve the wallet address
async fn get_address(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetAddressParams = parse_params(body)?;

    let wallet: &Arc<Wallet> = context.get()?;
    let address = if let Some(data) = params.integrated_data {
        wallet.get_address_with(data)
    } else {
        wallet.get_address()
    };

    Ok(json!(address))
}

// Split an integrated address into its address and data
async fn split_address(_: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: SplitAddressParams = parse_params(body)?;
    let address = params.address;

    let (data, address) = address.extract_data();
    let integrated_data = data.ok_or(InternalRpcError::InvalidParams("Address is not an integrated address"))?;
    let size = integrated_data.size();

    Ok(json!(SplitAddressResult {
        address,
        integrated_data,
        size
    }))
}

// Estimate the extra data size for a list of destinations
async fn estimate_extra_data_size(_: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: EstimateExtraDataSizeParams = parse_params(body)?;

    let mut size = 0;
    for data in &params.destinations {
        if let Some(extra_data) = data.get_extra_data() {
            size += ExtraData::estimate_size(extra_data)
        }
    }

    Ok(json!(EstimateExtraDataSizeResult {
        size
    }))
}

// Retrieve the network info
async fn network_info(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }

    let wallet: &Arc<Wallet> = context.get()?;
    let network_handler = wallet.get_network_handler().lock().await;
    if let Some(handler) = network_handler.as_ref() {
        let api = handler.get_api();
        let inner = api.get_info().await?;
        Ok(json!(NetworkInfoResult {
            inner,
            connected_to: api.get_client().get_target().to_owned(),
        }))
    } else {
        Err(InternalRpcError::InvalidRequestStr("Wallet is not connected to a daemon"))
    }
}

// Rescan the wallet from the provided topoheight (or from the beginning if not provided)
async fn rescan(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: RescanParams = parse_params(body)?;
    let wallet: &Arc<Wallet> = context.get()?;
    wallet.rescan(params.until_topoheight.unwrap_or(0), params.auto_reconnect).await?;
    Ok(json!(true))
}

// Retrieve the balance of the wallet for a specific asset
// By default, it will returns 0 if no balance is found on disk
async fn get_balance(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetBalanceParams = parse_params(body)?;
    let asset = params.asset.unwrap_or(XELIS_ASSET);
    let wallet: &Arc<Wallet> = context.get()?;
    let storage = wallet.get_storage().read().await;

    // If the asset is not found, it will returns 0
    // Use has_balance below to check if the wallet has a balance for a specific asset
    let balance = storage.get_plaintext_balance_for(&asset).await.unwrap_or(0);
    Ok(json!(balance))
}

// Check if the wallet has a balance for a specific asset
async fn has_balance(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetBalanceParams = parse_params(body)?;
    let asset = params.asset.unwrap_or(XELIS_ASSET);
    let wallet: &Arc<Wallet> = context.get()?;
    let storage = wallet.get_storage().read().await;

    let exist = storage.has_balance_for(&asset).await.context("Error while checking if balance exists")?;
    Ok(json!(exist))
}

// Retrieve all tracked assets by wallet
async fn get_tracked_assets(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }

    let wallet: &Arc<Wallet> = context.get()?;
    let storage = wallet.get_storage().read().await;
    let tracked_assets = storage.get_assets().await?;

    Ok(json!(tracked_assets))
}

// Retrieve decimals used by an asset
async fn get_asset_precision(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetAssetPrecisionParams = parse_params(body)?;

    let wallet: &Arc<Wallet> = context.get()?;
    let storage = wallet.get_storage().read().await;
    let precision = storage.get_asset_decimals(&params.asset)?;
    Ok(json!(precision))
}

// Retrieve a transaction from the wallet storage using its hash
async fn get_transaction(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetTransactionParams = parse_params(body)?;

    let wallet: &Arc<Wallet> = context.get()?;
    let storage = wallet.get_storage().read().await;
    let transaction = storage.get_transaction(&params.hash)?;

    Ok(json!(transaction.serializable(wallet.get_network().is_mainnet())))
}

// Build a transaction and broadcast it if requested
async fn build_transaction(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: BuildTransactionParams = parse_params(body)?;
    let wallet: &Arc<Wallet> = context.get()?;
    // request ask to broadcast the TX but wallet is not connected to any daemon
    if !wallet.is_online().await && params.broadcast {
        return Err(WalletError::NotOnlineMode)?
    }

    if !params.broadcast && !params.tx_as_hex {
        return Err(InternalRpcError::InvalidParams("Invalid params, should either be broadcasted, or returned in hex format"))
    }

    // create the TX
    // The lock is kept until the TX is applied to the storage
    // So even if we have few requests building a TX, they wait for the previous one to be applied
    let mut storage = wallet.get_storage().write().await;
    let (mut state, tx) = wallet.create_transaction_with_storage(&storage, params.tx_type, params.fee.unwrap_or_default(), params.nonce).await?;

    // if requested, broadcast the TX ourself
    if params.broadcast {
        if let Err(e) = wallet.submit_transaction(&tx).await {
            warn!("Clearing Tx cache & unconfirmed balances because of broadcasting error: {}", e);
            storage.clear_tx_cache();
            storage.delete_unconfirmed_balances().await;
            return Err(e.into());
        }
    }

    state.apply_changes(&mut storage).await
        .context("Error while applying state changes")?;

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

// Build a transaction by giving the encrypted balances directly
async fn build_transaction_offline(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: BuildTransactionOfflineParams = parse_params(body)?;
    let wallet: &Arc<Wallet> = context.get()?;

    // Create the state with the provided balances
    let mut state = TransactionBuilderState::new(wallet.get_network().is_mainnet(), params.reference, params.nonce);

    for (hash, mut ciphertext) in params.balances {
        let compressed = ciphertext.decompressed().context(format!("Error decompressing ciphertext {}", hash))?;
        let amount = wallet.decrypt_ciphertext(compressed.clone()).await?;

        state.add_balance(hash, Balance {
            amount,
            ciphertext
        });
    }

    let tx = wallet.create_transaction_with(&mut state, params.tx_type, params.fee)?;
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

// Clear the transaction cache
async fn clear_tx_cache(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }

    let wallet: &Arc<Wallet> = context.get()?;
    let mut storage = wallet.get_storage().write().await;
    storage.clear_tx_cache();

    Ok(json!(true))
}

// Estimate fees for a transaction
async fn estimate_fees(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: EstimateFeesParams = parse_params(body)?;
    let wallet: &Arc<Wallet> = context.get()?;
    let fees = wallet.estimate_fees(params.tx_type).await?;

    Ok(json!(fees))
}

// List transactions from the wallet storage
async fn list_transactions(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: ListTransactionsParams = parse_params(body)?;
    if let Some(addr) = &params.address {
        if !addr.is_normal() {
            return Err(InternalRpcError::InvalidParams("Address should be in normal format (not integrated address)"))
        }
    }

    let wallet: &Arc<Wallet> = context.get()?;
    let storage = wallet.get_storage().read().await;
    let opt_key = params.address.map(|addr| addr.to_public_key());
    
    let mainnet = wallet.get_network().is_mainnet();
    let txs = storage.get_filtered_transactions(opt_key.as_ref(), params.asset.as_ref(), params.min_topoheight, params.max_topoheight, params.accept_incoming, params.accept_outgoing, params.accept_coinbase, params.accept_burn, params.query.as_ref())?
        .into_iter()
        .map(|tx| tx.serializable(mainnet))
        .collect::<Vec<_>>();

    Ok(json!(txs))
}

// Check if the wallet is currently connected to a daemon
async fn is_online(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }

    let wallet: &Arc<Wallet> = context.get()?;
    let is_connected = wallet.is_online().await;
    Ok(json!(is_connected))
}

// Connect the wallet to a daemon if not already connected
async fn set_online_mode(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: SetOnlineModeParams = parse_params(body)?;

    let wallet: &Arc<Wallet> = context.get()?;
    if wallet.is_online().await {
        return Err(InternalRpcError::InvalidRequestStr("Wallet is already connected to a daemon"))
    }

    wallet.set_online_mode(&params.daemon_address, params.auto_reconnect).await?;

    Ok(json!(true))
}

// Connect the wallet to a daemon if not already connected
async fn set_offline_mode(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    if body != Value::Null {
        return Err(InternalRpcError::UnexpectedParams)
    }

    let wallet: &Arc<Wallet> = context.get()?;
    if !wallet.is_online().await {
        return Err(InternalRpcError::InvalidRequestStr("Wallet is already in offline mode"))
    }

    wallet.set_offline_mode().await?;

    Ok(json!(true))
}

// Sign any data converted in bytes format
async fn sign_data(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: DataElement = parse_params(body)?;

    let wallet: &Arc<Wallet> = context.get()?;
    let signature = wallet.sign_data(&params.to_bytes());
    Ok(json!(signature))
}

// In EncryptedStorage, custom trees are already prefixed
async fn get_tree_name(context: &Context, tree: String) -> Result<String, InternalRpcError> {
    // If the API is not used through XSWD, we don't need to prefix the tree name with the app id
    if !context.has::<&WebSocketSessionShared<XSWDWebSocketHandler<Arc<Wallet>>>>() {
        return Ok(tree)
    }

    // Retrieve the app data to get its id and to have section of trees between differents dApps
    let session: &WebSocketSessionShared<XSWDWebSocketHandler<Arc<Wallet>>> = context.get()?;
    let xswd = session.get_server().get_handler();
    let applications = xswd.get_applications().read().await;
    let app = applications.get(session).ok_or_else(|| InternalRpcError::InvalidContext)?;

    Ok(format!("{}-{}", app.get_id(), tree))
}

// Returns all keys available in the selected tree using the Query filter
async fn get_matching_keys(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetMatchingKeysParams = parse_params(body)?;
    if let Some(query) = &params.query {
        if query.is_for_element() {
            return Err(InternalRpcError::InvalidParams("Invalid key query, should be a QueryValue"))
        }
    }

    let wallet: &Arc<Wallet> = context.get()?;
    let tree = get_tree_name(&context, params.tree).await?;
    let storage = wallet.get_storage().read().await;
    let keys = storage.get_custom_tree_keys(&tree, &params.query)?;

    Ok(json!(keys))
}

// Count all entries available in the selected tree using the Query filter
async fn count_matching_entries(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: CountMatchingEntriesParams = parse_params(body)?;
    let wallet: &Arc<Wallet> = context.get()?;
    let tree = get_tree_name(&context, params.tree).await?;
    let storage = wallet.get_storage().read().await;
    let count = storage.count_custom_tree_entries(&tree, &params.key, &params.value)?;

    Ok(json!(count))
}

// Retrieve the data from the encrypted storage using its key and tree
async fn get_value_from_key(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: GetValueFromKeyParams = parse_params(body)?;
    let wallet: &Arc<Wallet> = context.get()?;
    let tree = get_tree_name(&context, params.tree).await?;

    let storage = wallet.get_storage().read().await;
    let value = storage.get_custom_data(&tree, &params.key)?;

    Ok(json!(value))
}

// Store data in the requested tree with the key set
async fn store(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: StoreParams = parse_params(body)?;
    let wallet: &Arc<Wallet> = context.get()?;
    let tree = get_tree_name(&context, params.tree).await?;
    let mut storage = wallet.get_storage().write().await;
    storage.set_custom_data(&tree, &params.key, &params.value)?;
    Ok(json!(true))
}

// Delete data in the requested tree with the key set
async fn delete(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: DeleteParams = parse_params(body)?;
    let wallet: &Arc<Wallet> = context.get()?;
    let tree = get_tree_name(&context, params.tree).await?;
    let mut storage = wallet.get_storage().write().await;
    storage.delete_custom_data(&tree, &params.key)?;
    Ok(json!(true))
}

// Delete all entries in the requested tree
async fn delete_tree_entries(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: DeleteParams = parse_params(body)?;
    let wallet: &Arc<Wallet> = context.get()?;
    let tree = get_tree_name(&context, params.tree).await?;
    let mut storage = wallet.get_storage().write().await;
    storage.clear_custom_tree(&tree)?;
    Ok(json!(true))
}

// Verify if the key is present in the requested tree
async fn has_key(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: HasKeyParams = parse_params(body)?;
    let wallet: &Arc<Wallet> = context.get()?;
    let tree = get_tree_name(&context, params.tree).await?;

    let storage = wallet.get_storage().read().await;
    Ok(json!(storage.has_custom_data(&tree, &params.key)?))
}

// Search in DB all entries based on filters set
async fn query_db(context: &Context, body: Value) -> Result<Value, InternalRpcError> {
    let params: QueryDBParams = parse_params(body)?;
    if let Some(query) = &params.key {
        if query.is_for_element() {
            return Err(InternalRpcError::InvalidParams("Invalid key query, should be a QueryValue"))
        }
    }

    let wallet: &Arc<Wallet> = context.get()?;
    let tree = get_tree_name(&context, params.tree).await?;
    let storage = wallet.get_storage().read().await;
    let result = storage.query_db(&tree, params.key, params.value, params.return_on_first)?;
    Ok(json!(result))
}