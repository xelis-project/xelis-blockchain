use std::{sync::Arc, borrow::Cow};

use anyhow::Context;
use log::info;
use xelis_common::{rpc_server::{RPCHandler, InternalRpcError, parse_params}, config::VERSION, async_handler, api::{wallet::{BuildTransactionParams, FeeBuilder, TransactionResponse}, DataHash}, crypto::hash::Hashable};
use serde_json::{Value, json};
use crate::wallet::{Wallet, WalletError};

pub fn register_methods(handler: &mut RPCHandler<Arc<Wallet>>) {
    info!("Registering RPC methods...");
    handler.register_method("version", async_handler!(version));
    handler.register_method("build_transaction", async_handler!(build_transaction));
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