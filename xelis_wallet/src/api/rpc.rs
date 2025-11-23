use std::{sync::Arc, borrow::Cow};
use anyhow::Context as AnyContext;
use cfg_if::cfg_if;
use itertools::Itertools;
use xelis_common::{
    api::{
        query::QueryResult,
        wallet::*,
        DataElement,
        DataHash,
        DataValue,
        SplitAddressParams,
        SplitAddressResult
    },
    asset::AssetData,
    async_handler,
    block::TopoHeight,
    config::{VERSION, XELIS_ASSET},
    context::Context,
    crypto::{Address, Hash, Hashable, KeyPair, Signature},
    network::Network,
    rpc::{
        InternalRpcError,
        RPCHandler
    },
    serializer::Serializer,
    transaction::{
        builder::TransactionBuilder,
        extra_data::{ExtraData, PlaintextExtraData},
        multisig::{MultiSig, SignatureId}
    }
};
use crate::{
    api::XSWDAppId,
    error::WalletError,
    storage::Balance,
    transaction_builder::TransactionBuilderState,
    wallet::Wallet
};

use log::{debug, info, warn};

// Register all RPC methods
pub fn register_methods(handler: &mut RPCHandler<Arc<Wallet>>) {
    info!("Registering RPC methods...");
    handler.register_method_no_params("get_version", async_handler!(get_version, single));
    handler.register_method_no_params("get_network", async_handler!(get_network, single));
    handler.register_method_no_params("get_nonce", async_handler!(get_nonce, single));
    handler.register_method_no_params("get_topoheight", async_handler!(get_topoheight, single));
    handler.register_method_with_params("get_address", async_handler!(get_address));
    handler.register_method_with_params("split_address", async_handler!(split_address));
    handler.register_method_with_params("rescan", async_handler!(rescan));
    handler.register_method_with_params("get_balance", async_handler!(get_balance));
    handler.register_method_with_params("has_balance", async_handler!(has_balance));
    handler.register_method_with_params("get_tracked_assets", async_handler!(get_tracked_assets));
    handler.register_method_with_params("is_asset_tracked", async_handler!(is_asset_tracked));
    handler.register_method_with_params("track_asset", async_handler!(track_asset));
    handler.register_method_with_params("untrack_asset", async_handler!(untrack_asset));
    handler.register_method_with_params("get_asset_precision", async_handler!(get_asset_precision));
    handler.register_method_with_params("get_assets", async_handler!(get_assets));
    handler.register_method_with_params("get_asset", async_handler!(get_asset));
    handler.register_method_with_params("get_transaction", async_handler!(get_transaction));
    handler.register_method_with_params("search_transaction", async_handler!(search_transaction));
    handler.register_method_with_params("dump_transaction", async_handler!(dump_transaction));
    handler.register_method_with_params("build_transaction", async_handler!(build_transaction));
    handler.register_method_with_params("build_transaction_offline", async_handler!(build_transaction_offline));
    handler.register_method_with_params("build_unsigned_transaction", async_handler!(build_unsigned_transaction));
    handler.register_method_with_params("finalize_unsigned_transaction", async_handler!(finalize_unsigned_transaction));
    handler.register_method_with_params("sign_unsigned_transaction", async_handler!(sign_unsigned_transaction));

    handler.register_method_no_params("clear_tx_cache", async_handler!(clear_tx_cache, single));
    handler.register_method_with_params("list_transactions", async_handler!(list_transactions));
    handler.register_method_no_params("is_online", async_handler!(is_online, single));
    handler.register_method_with_params("set_online_mode", async_handler!(set_online_mode));
    handler.register_method_no_params("set_offline_mode", async_handler!(set_offline_mode, single));
    handler.register_method_with_params("sign_data", async_handler!(sign_data));
    handler.register_method_with_params("estimate_fees", async_handler!(estimate_fees));
    handler.register_method_with_params("estimate_extra_data_size", async_handler!(estimate_extra_data_size));
    handler.register_method_no_params("network_info", async_handler!(network_info, single));
    handler.register_method_with_params("decrypt_extra_data", async_handler!(decrypt_extra_data));
    handler.register_method_with_params("decrypt_ciphertext", async_handler!(decrypt_ciphertext));

    // These functions allow to have an encrypted DB directly in the wallet storage
    // You can retrieve keys, values, have differents trees, and store values
    // It is restricted in XSWD context (each app access to their own trees), and open to everything in RPC
    // Keys and values can be anything
    handler.register_method_with_params("get_matching_keys", async_handler!(get_matching_keys));
    handler.register_method_with_params("count_matching_entries", async_handler!(count_matching_entries));
    handler.register_method_with_params("get_value_from_key", async_handler!(get_value_from_key));
    handler.register_method_with_params("store", async_handler!(store));
    handler.register_method_with_params("delete", async_handler!(delete));
    handler.register_method_with_params("delete_tree_entries", async_handler!(delete_tree_entries));
    handler.register_method_with_params("has_key", async_handler!(has_key));
    handler.register_method_with_params("query_db", async_handler!(query_db));
}

// Retrieve the version of the wallet
async fn get_version(_: &Context) -> Result<&'static str, InternalRpcError> {
    Ok(VERSION)
}

// Retrieve the network of the wallet
async fn get_network(context: &Context) -> Result<Network, InternalRpcError> {
    let wallet: &Arc<Wallet> = context.get()?;
    let network = wallet.get_network();
    Ok(*network)
}

// Retrieve the current nonce of the wallet
async fn get_nonce(context: &Context) -> Result<u64, InternalRpcError> {
    let wallet: &Arc<Wallet> = context.get()?;
    let storage = wallet.get_storage().read().await;
    let nonce = storage.get_nonce()?;
    Ok(nonce)
}

// Retrieve the current topoheight until which the wallet is synced
async fn get_topoheight(context: &Context) -> Result<TopoHeight, InternalRpcError> {
    let wallet: &Arc<Wallet> = context.get()?;
    let storage = wallet.get_storage().read().await;
    let topoheight = storage.get_synced_topoheight()?;
    Ok(topoheight)
}

// Retrieve the wallet address
async fn get_address(context: &Context, params: GetAddressParams) -> Result<Address, InternalRpcError> {
    let wallet: &Arc<Wallet> = context.get()?;
    let address = if let Some(data) = params.integrated_data {
        wallet.get_address_with(data)
    } else {
        wallet.get_address()
    };

    Ok(address)
}

// Split an integrated address into its address and data
async fn split_address(_: &Context, params: SplitAddressParams) -> Result<SplitAddressResult, InternalRpcError> {
    let address = params.address;

    let (data, address) = address.extract_data();
    let integrated_data = data.ok_or(InternalRpcError::InvalidParams("Address is not an integrated address"))?;
    let size = integrated_data.size();

    Ok(SplitAddressResult {
        address,
        integrated_data,
        size
    })
}

// Estimate the extra data size for a list of destinations
async fn estimate_extra_data_size(_: &Context, params: EstimateExtraDataSizeParams) -> Result<EstimateExtraDataSizeResult, InternalRpcError> {
    let mut size = 0;
    for data in &params.destinations {
        if let Some(extra_data) = data.get_extra_data() {
            size += ExtraData::estimate_size(extra_data)
        }
    }

    Ok(EstimateExtraDataSizeResult {
        size
    })
}

// Retrieve the network info
async fn network_info(context: &Context) -> Result<NetworkInfoResult, InternalRpcError> {
    let wallet: &Arc<Wallet> = context.get()?;

    cfg_if! {
        if #[cfg(feature = "network_handler")] {
            let network_handler = wallet.get_network_handler().lock().await;
            if let Some(handler) = network_handler.as_ref() {
                let api = handler.get_api();
                let inner = api.get_info().await?;
                Ok(NetworkInfoResult {
                    inner,
                    connected_to: api.get_client().get_target().to_owned(),
                })
            } else {
                Err(WalletError::NotOnlineMode.into())
            }
        } else {
            Err(WalletError::Unsupported.into())
        }
    }
}

// Decrypt extra data using the wallet private key
async fn decrypt_extra_data(context: &Context, params: DecryptExtraDataParams<'_>) -> Result<PlaintextExtraData, InternalRpcError> {
    let wallet: &Arc<Wallet> = context.get()?;
    let version = {
        let storage = wallet.get_storage().read().await;
        storage.get_tx_version().await?
    };

    let data = wallet.decrypt_extra_data(params.extra_data.into_owned(), None, params.role, version)
        .context("Error while decrypting extra data")?;

    Ok(data)
}

async fn decrypt_ciphertext(context: &Context, params: DecryptCiphertextParams<'_>) -> Result<Option<u64>, InternalRpcError> {
    let wallet: &Arc<Wallet> = context.get()?;
    let decompressed = params.ciphertext.decompress().context("Error while decompressing ciphertext")?;
    let amount = wallet.decrypt_ciphertext_with(decompressed, params.max_supply).await
        .context("Error while decrypting ciphertext")?;

    Ok(amount)
}

// Rescan the wallet from the provided topoheight (or from the beginning if not provided)
async fn rescan(context: &Context, params: RescanParams) -> Result<bool, InternalRpcError> {
    let wallet: &Arc<Wallet> = context.get()?;

    cfg_if! {
        if #[cfg(feature = "network_handler")] {
            wallet.rescan(params.until_topoheight.unwrap_or(0), params.auto_reconnect).await?;

            Ok(true)
        } else {
            Ok(false)
        }
    }
}

// Retrieve the balance of the wallet for a specific asset
// By default, it will returns 0 if no balance is found on disk
async fn get_balance(context: &Context, params: GetBalanceParams) -> Result<u64, InternalRpcError> {
    let asset = params.asset.unwrap_or(XELIS_ASSET);
    let wallet: &Arc<Wallet> = context.get()?;
    let storage = wallet.get_storage().read().await;

    // If the asset is not found, it will returns 0
    // Use has_balance below to check if the wallet has a balance for a specific asset
    let balance = storage.get_plaintext_balance_for(&asset).await.unwrap_or(0);
    Ok(balance)
}

// Check if the wallet has a balance for a specific asset
async fn has_balance(context: &Context, params: GetBalanceParams) -> Result<bool, InternalRpcError> {
    let asset = params.asset.unwrap_or(XELIS_ASSET);
    let wallet: &Arc<Wallet> = context.get()?;
    let storage = wallet.get_storage().read().await;

    let exist = storage.has_balance_for(&asset).await.context("Error while checking if balance exists")?;
    Ok(exist)
}

// Retrieve all tracked assets by wallet
async fn get_tracked_assets(context: &Context, params: GetAssetsParams) -> Result<Vec<Hash>, InternalRpcError> {
    let wallet: &Arc<Wallet> = context.get()?;
    let maximum = if let Some(max) = params.maximum {
        if max > MAX_ASSETS {
            return Err(InternalRpcError::InvalidParams("Maximum is bigger than limit"))
        }
        max
    } else {
        MAX_ASSETS
    };

    // In case of a huge reorg, a tracked asset may be inexistant if the asset got removed temporarily
    // This must be taken in count
    let storage = wallet.get_storage().read().await;
    let tracked_assets = storage.get_tracked_assets()?
        .skip(params.skip.unwrap_or(0))
        .take(maximum)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(tracked_assets)
}

async fn is_asset_tracked(context: &Context, params: IsAssetTrackedParams<'_>) -> Result<bool, InternalRpcError> {
    let wallet: &Arc<Wallet> = context.get()?;
    let storage = wallet.get_storage().read().await;

    // Check if the asset is tracked
    let is_tracked = storage.is_asset_tracked(&params.asset).await?;
    Ok(is_tracked)
}

// Retrieve decimals used by an asset
async fn get_asset_precision(context: &Context, params: GetAssetPrecisionParams<'_>) -> Result<u8, InternalRpcError> {
    let wallet: &Arc<Wallet> = context.get()?;
    let storage = wallet.get_storage().read().await;
    let data = storage.get_asset(&params.asset).await?;
    Ok(data.get_decimals())
}

const MAX_ASSETS: usize = 100;

// Retrieve all the assets that the wallet is aware of
async fn get_assets(context: &Context, params: GetAssetsParams) -> Result<Vec<GetAssetsEntry>, InternalRpcError> {
    let wallet: &Arc<Wallet> = context.get()?;

    let maximum = if let Some(max) = params.maximum {
        if max > MAX_ASSETS {
            return Err(InternalRpcError::InvalidParams("Maximum is bigger than limit"))
        }
        max
    } else {
        MAX_ASSETS
    };

    let storage = wallet.get_storage().read().await;
    let assets = storage.get_assets_with_data().await?
        .skip(params.skip.unwrap_or(0))
        .take(maximum)
        .map_ok(|(asset, data)| GetAssetsEntry {
                asset,
                data
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(assets)
}

// Retrieve an asset from the wallet storage using its hash
async fn get_asset(context: &Context, params: GetAssetPrecisionParams<'_>) -> Result<AssetData, InternalRpcError> {
    let wallet: &Arc<Wallet> = context.get()?;
    let storage = wallet.get_storage().read().await;
    let data = storage.get_asset(&params.asset).await?;
    Ok(data)
}

// Retrieve a transaction from the wallet storage using its hash
async fn get_transaction(context: &Context, params: GetTransactionParams) -> Result<TransactionEntry, InternalRpcError> {
    let wallet: &Arc<Wallet> = context.get()?;
    let storage = wallet.get_storage().read().await;
    if !storage.has_transaction(&params.hash)? {
        return Err(InternalRpcError::InvalidParams("Transaction is not found in wallet"))
    }

    let transaction = storage.get_transaction(&params.hash)?;

    Ok(transaction.serializable(wallet.get_network().is_mainnet()))
}

// Debug rpc method to perform a search across all entries for a transaction from the wallet storage using its hash
async fn search_transaction(context: &Context, params: SearchTransactionParams<'_>) -> Result<SearchTransactionResult, InternalRpcError> {
    let wallet: &Arc<Wallet> = context.get()?;
    let storage = wallet.get_storage().read().await;

    let index = storage.get_transaction_id(&params.hash)?;
    if storage.has_transaction(&params.hash)? {
        let transaction = storage.get_transaction(&params.hash)?;

        return Ok(SearchTransactionResult {
            transaction: Some(transaction.serializable(wallet.get_network().is_mainnet())),
            index,
            is_raw_search: false
        });
    }

    let transaction = storage.search_transaction(&params.hash)?
        .map(|transaction| transaction.serializable(wallet.get_network().is_mainnet()));

    Ok(SearchTransactionResult {
        transaction,
        index,
        is_raw_search: true
    })
}

// Dump the TX in hex format
async fn dump_transaction(context: &Context, params: GetTransactionParams) -> Result<String, InternalRpcError> {
    let wallet: &Arc<Wallet> = context.get()?;
    let storage = wallet.get_storage().read().await;
    let transaction = storage.get_transaction(&params.hash)?;

    Ok(transaction.to_hex())
}

// Build a transaction and broadcast it if requested
async fn build_transaction(context: &Context, params: BuildTransactionParams) -> Result<TransactionResponse<'static>, InternalRpcError> {
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

    if params.signers.len() > u8::MAX as usize {
        return Err(InternalRpcError::InvalidParams("Too many signers"))
    }

    let version = if let Some(v) = params.tx_version {
        v
    } else {
        storage.get_tx_version().await?
    };

    let mut state = wallet.create_transaction_state_with_storage(&storage, &params.tx_type, params.fee, params.base_fee, params.nonce, params.fee_limit).await?;

    let tx = if params.signers.is_empty() {
        wallet.create_transaction_with(&mut state, None, version, params.tx_type, params.fee)?
    } else {
        let builder = TransactionBuilder::new(version, wallet.get_public_key().clone(), Some(params.signers.len() as u8), params.tx_type, params.fee);
        let mut unsigned = builder.build_unsigned(&mut state, wallet.get_keypair())
            .context("Error while building unsigned transaction")?;

        for signer in params.signers {
            let keypair = KeyPair::from_private_key(signer.private_key);
            unsigned.sign_multisig(&keypair, signer.id);
        }

        let tx = unsigned.finalize(wallet.get_keypair());
        state.set_tx_hash_built(tx.hash());

        tx
    };

    // if requested, broadcast the TX ourself
    if params.broadcast {
        if let Err(e) = wallet.submit_transaction(&tx).await {
            warn!("Clearing Tx cache & unconfirmed balances because of broadcasting error: {}", e);
            debug!("TX HEX: {}", tx.to_hex());
            storage.clear_tx_cache().await;
            storage.delete_unconfirmed_balances().await;
            return Err(e.into());
        }
    }

    state.apply_changes(&mut storage).await
        .context("Error while applying state changes")?;

    // returns the created TX and its hash
    Ok(TransactionResponse {
        tx_as_hex: if params.tx_as_hex {
            Some(hex::encode(tx.to_bytes()))
        } else {
            None
        },
        inner: DataHash {
            hash: Cow::Owned(tx.hash()),
            data: Cow::Owned(tx)
        }
    })
}

// Build a transaction by giving the encrypted balances directly
async fn build_transaction_offline(context: &Context, params: BuildTransactionOfflineParams) -> Result<TransactionResponse<'static>, InternalRpcError> {
    let wallet: &Arc<Wallet> = context.get()?;

    // Create the state with the provided balances
    let mut state = TransactionBuilderState::new(wallet.get_network().is_mainnet(), params.reference, params.nonce, params.fee_limit);
    state.set_base_fee(params.base_fee);

    for (hash, mut ciphertext) in params.balances {
        let compressed = ciphertext.decompressed()
            .context(format!("Error decompressing ciphertext {}", hash))?;
        let amount = wallet.decrypt_ciphertext_with(compressed.clone(), None).await?
            .context(format!("Couldn't decrypt ciphertext for asset {}", hash))?;

        state.add_balance(hash, Balance {
            amount,
            ciphertext,
            topoheight: state.get_reference().topoheight,
        });
    }

    if params.signers.len() > u8::MAX as usize {
        return Err(InternalRpcError::InvalidParams("Too many signers"))
    }

    let version = if let Some(v) = params.tx_version {
        v
    } else {
        let storage = wallet.get_storage().read().await;
        storage.get_tx_version().await?
    };

    let tx = if params.signers.is_empty() {
        wallet.create_transaction_with(&mut state, None, version, params.tx_type, params.fee)?
    } else {
        let builder = TransactionBuilder::new(version, wallet.get_public_key().clone(), Some(params.signers.len() as u8), params.tx_type, params.fee);
        let mut unsigned = builder.build_unsigned(&mut state, wallet.get_keypair())
            .context("Error while building unsigned transaction")?;

        for signer in params.signers {
            let keypair = KeyPair::from_private_key(signer.private_key);
            unsigned.sign_multisig(&keypair, signer.id);
        }

        let tx = unsigned.finalize(wallet.get_keypair());
        state.set_tx_hash_built(tx.hash());

        tx
    };

    Ok(TransactionResponse {
        tx_as_hex: if params.tx_as_hex {
            Some(hex::encode(tx.to_bytes()))
        } else {
            None
        },
        inner: DataHash {
            hash: Cow::Owned(tx.hash()),
            data: Cow::Owned(tx)
        }
    })
}

async fn build_unsigned_transaction(context: &Context, params: BuildUnsignedTransactionParams) -> Result<UnsignedTransactionResponse, InternalRpcError> {
    let wallet: &Arc<Wallet> = context.get()?;

    // create the TX
    // The lock is kept until the TX is applied to the storage
    // So even if we have few requests building a TX, they wait for the previous one to be applied
    let mut storage = wallet.get_storage().write().await;
    let mut state = wallet.create_transaction_state_with_storage(&storage, &params.tx_type, params.fee, params.base_fee, params.nonce, params.fee_limit).await?;

    let version = storage.get_tx_version().await?;
    let threshold = storage.get_multisig_state().await?
        .map(|state| state.payload.threshold);

    // Generate the TX
    let builder = TransactionBuilder::new(version, wallet.get_public_key().clone(), threshold, params.tx_type, params.fee);
    let unsigned = builder.build_unsigned(&mut state, wallet.get_keypair())
        .context("Error while building unsigned transaction")?;

    state.apply_changes(&mut storage).await
        .context("Error while applying state changes")?;

    // returns the created TX and its hash
    Ok(UnsignedTransactionResponse {
        tx_as_hex: if params.tx_as_hex {
            Some(hex::encode(unsigned.to_bytes()))
        } else {
            None
        },
        hash: unsigned.get_hash_for_multisig(),
        inner: unsigned,
        threshold
    })
}

// Finalize an unsigned transaction by signing it
// Add the signatures to the transaction if a multisig is set
async fn finalize_unsigned_transaction(context: &Context, params: FinalizeUnsignedTransactionParams) -> Result<TransactionResponse<'static>, InternalRpcError> {
    let wallet: &Arc<Wallet> = context.get()?;

    let mut unsigned = params.unsigned;
    if params.signatures.is_empty() != unsigned.multisig().is_some() {
        return Err(InternalRpcError::InvalidParams("Invalid signatures"))
    }

    if unsigned.source() != wallet.get_public_key() {
        return Err(InternalRpcError::InvalidParams("Invalid source"))
    }

    let keypair = wallet.get_keypair();

    if !params.signatures.is_empty() {
        let mut multisig = MultiSig::new();
        for signature in params.signatures {
            multisig.add_signature(signature);
        }

        unsigned.set_multisig(multisig);
    }

    let tx = unsigned.0.finalize(keypair);
    
    let mut storage = wallet.get_storage().write().await;
    let mut state = TransactionBuilderState::from_tx(&storage, &tx, wallet.get_network().is_mainnet()).await?;

    if params.broadcast {
        if let Err(e) = wallet.submit_transaction(&tx).await {
            warn!("Clearing Tx cache & unconfirmed balances because of broadcasting error: {}", e);
            debug!("TX HEX: {}", tx.to_hex());
            storage.clear_tx_cache().await;
            storage.delete_unconfirmed_balances().await;
            return Err(e.into());
        }
    }

    state.apply_changes(&mut storage).await
        .context("Error while applying state changes")?;

    Ok(TransactionResponse {
        tx_as_hex: if params.tx_as_hex {
            Some(hex::encode(tx.to_bytes()))
        } else {
            None
        },
        inner: DataHash {
            hash: Cow::Owned(tx.hash()),
            data: Cow::Owned(tx)
        }
    })
}

// Sign a unsigned transaction as a multisig member
async fn sign_unsigned_transaction(context: &Context, params: SignUnsignedTransactionParams) -> Result<SignatureId, InternalRpcError> {
    let wallet: &Arc<Wallet> = context.get()?;

    let signature = wallet.sign_data(params.hash.as_bytes());
    Ok(SignatureId {
        id: params.signer_id,
        signature
    })
}

// Clear the transaction cache
async fn clear_tx_cache(context: &Context) -> Result<bool, InternalRpcError> {
    let wallet: &Arc<Wallet> = context.get()?;
    let mut storage = wallet.get_storage().write().await;
    storage.clear_tx_cache().await;

    Ok(true)
}

// Estimate fees for a transaction
async fn estimate_fees(context: &Context, params: EstimateFeesParams) -> Result<u64, InternalRpcError> {
    let wallet: &Arc<Wallet> = context.get()?;
    let fees = wallet.estimate_fees(params.tx_type, params.fee, params.base_fee).await?;

    Ok(fees)
}

// List transactions from the wallet storage
async fn list_transactions(context: &Context, params: ListTransactionsParams) -> Result<Vec<TransactionEntry>, InternalRpcError> {
    if let Some(addr) = &params.address {
        if !addr.is_normal() {
            return Err(InternalRpcError::InvalidParams("Address should be in normal format (not integrated address)"))
        }
    }

    let wallet: &Arc<Wallet> = context.get()?;
    let storage = wallet.get_storage().read().await;
    let opt_key = params.address.map(|addr| addr.to_public_key());
    
    let mainnet = wallet.get_network().is_mainnet();
    let txs = storage.get_filtered_transactions(
        opt_key.as_ref(),
        params.asset.as_ref(),
        params.min_topoheight,
        params.max_topoheight,
        params.accept_incoming,
        params.accept_outgoing,
        params.accept_coinbase,
        params.accept_burn,
        params.query.as_ref(),
        params.limit,
        params.skip,
    )?
        .into_iter()
        .map(|tx| tx.serializable(mainnet))
        .collect::<Vec<_>>();

    Ok(txs)
}

// Check if the wallet is currently connected to a daemon
async fn is_online(context: &Context) -> Result<bool, InternalRpcError> {
    let wallet: &Arc<Wallet> = context.get()?;
    let is_connected = wallet.is_online().await;
    Ok(is_connected)
}

// Connect the wallet to a daemon if not already connected
async fn set_online_mode(context: &Context, params: SetOnlineModeParams) -> Result<bool, InternalRpcError> {
    let wallet: &Arc<Wallet> = context.get()?;
    if wallet.is_online().await {
        return Err(InternalRpcError::InvalidRequestStr("Wallet is already connected to a daemon"))
    }

    cfg_if! {
        if #[cfg(feature = "network_handler")] {
            wallet.set_online_mode(&params.daemon_address, params.auto_reconnect).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

// Connect the wallet to a daemon if not already connected
async fn set_offline_mode(context: &Context) -> Result<bool, InternalRpcError> {
    let wallet: &Arc<Wallet> = context.get()?;
    if !wallet.is_online().await {
        return Err(InternalRpcError::InvalidRequestStr("Wallet is already in offline mode"))
    }

    cfg_if! {
        if #[cfg(feature = "network_handler")] {
            wallet.set_offline_mode().await?;

            Ok(true)
        } else {
            Ok(false)
        }
    }
}

// Sign any data converted in bytes format
async fn sign_data(context: &Context, params: DataElement) -> Result<Signature, InternalRpcError> {
    let wallet: &Arc<Wallet> = context.get()?;
    let signature = wallet.sign_data(&params.to_bytes());
    Ok(signature)
}

// In EncryptedStorage, custom trees are already prefixed
async fn get_tree_name(context: &Context, tree: String) -> Result<String, InternalRpcError> {
    // If the API is not used through XSWD, we don't need to prefix the tree name with the app id
    if !context.has::<&XSWDAppId>() {
        return Ok(tree)
    }

    // Retrieve the app data to get its id and to have section of trees between differents dApps
    let xswd: &XSWDAppId = context.get()?;
    Ok(format!("{}-{}", xswd.0, tree))
}

// Returns all keys available in the selected tree using the Query filter
async fn get_matching_keys(context: &Context, params: GetMatchingKeysParams) -> Result<Vec<DataValue>, InternalRpcError> {
    if let Some(query) = &params.query {
        if query.is_for_element() {
            return Err(InternalRpcError::InvalidParams("Invalid key query, should be a QueryValue"))
        }
    }

    let wallet: &Arc<Wallet> = context.get()?;
    let tree = get_tree_name(&context, params.tree).await?;
    let storage = wallet.get_storage().read().await;
    let keys = storage.get_custom_tree_keys(&tree, &params.query, params.limit, params.skip)?;

    Ok(keys)
}

// Count all entries available in the selected tree using the Query filter
async fn count_matching_entries(context: &Context, params: CountMatchingEntriesParams) -> Result<usize, InternalRpcError> {
    let wallet: &Arc<Wallet> = context.get()?;
    let tree = get_tree_name(&context, params.tree).await?;
    let storage = wallet.get_storage().read().await;
    let count = storage.count_custom_tree_entries(&tree, &params.key, &params.value)?;

    Ok(count)
}

// Retrieve the data from the encrypted storage using its key and tree
async fn get_value_from_key(context: &Context, params: GetValueFromKeyParams) -> Result<DataElement, InternalRpcError> {
    let wallet: &Arc<Wallet> = context.get()?;
    let tree = get_tree_name(&context, params.tree).await?;

    let storage = wallet.get_storage().read().await;
    let value = storage.get_custom_data(&tree, &params.key)?;

    Ok(value)
}

// Store data in the requested tree with the key set
async fn store(context: &Context, params: StoreParams) -> Result<bool, InternalRpcError> {
    let wallet: &Arc<Wallet> = context.get()?;
    let tree = get_tree_name(&context, params.tree).await?;
    let mut storage = wallet.get_storage().write().await;
    storage.set_custom_data(&tree, &params.key, &params.value)?;
    Ok(true)
}

// Delete data in the requested tree with the key set
async fn delete(context: &Context, params: DeleteParams) -> Result<bool, InternalRpcError> {
    let wallet: &Arc<Wallet> = context.get()?;
    let tree = get_tree_name(&context, params.tree).await?;
    let mut storage = wallet.get_storage().write().await;
    storage.delete_custom_data(&tree, &params.key)?;
    Ok(true)
}

// Delete all entries in the requested tree
async fn delete_tree_entries(context: &Context, params: DeleteTreeEntriesParams) -> Result<bool, InternalRpcError> {
    let wallet: &Arc<Wallet> = context.get()?;
    let tree = get_tree_name(&context, params.tree).await?;
    let mut storage = wallet.get_storage().write().await;
    storage.clear_custom_tree(&tree)?;
    Ok(true)
}

// Verify if the key is present in the requested tree
async fn has_key(context: &Context, params: HasKeyParams) -> Result<bool, InternalRpcError> {
    let wallet: &Arc<Wallet> = context.get()?;
    let tree = get_tree_name(&context, params.tree).await?;

    let storage = wallet.get_storage().read().await;
    Ok(storage.has_custom_data(&tree, &params.key)?)
}

// Search in DB all entries based on filters set
async fn query_db(context: &Context, params: QueryDBParams) -> Result<QueryResult, InternalRpcError> {
    if let Some(query) = &params.key {
        if query.is_for_element() {
            return Err(InternalRpcError::InvalidParams("Invalid key query, should be a QueryValue"))
        }
    }

    let wallet: &Arc<Wallet> = context.get()?;
    let tree = get_tree_name(&context, params.tree).await?;
    let storage = wallet.get_storage().read().await;
    let result = storage.query_db(&tree, params.key, params.value, params.limit, params.skip)?;
    Ok(result)
}

// Track a new wallet asset
async fn track_asset(context: &Context, params: TrackAssetParams<'_>) -> Result<bool, InternalRpcError> {
    let wallet: &Arc<Wallet> = context.get()?;
    let tracked = wallet.track_asset(params.asset.into_owned()).await?;

    Ok(tracked)
}

// Untrack a wallet asset
async fn untrack_asset(context: &Context, params: TrackAssetParams<'_>) -> Result<bool, InternalRpcError> {
    let wallet: &Arc<Wallet> = context.get()?;
    let untracked = wallet.untrack_asset(params.asset.into_owned()).await?;
    Ok(untracked)
}