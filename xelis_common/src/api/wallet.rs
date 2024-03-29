use std::borrow::Cow;
use serde::{Deserialize, Serialize};
use crate::{
    crypto::{Address, Hash},
    transaction::{
        builder::{FeeBuilder, TransactionTypeBuilder},
        Transaction
    }
};
use super::{DataHash, DataElement, DataValue, query::Query};

#[derive(Serialize, Deserialize)]
pub struct BuildTransactionParams {
    #[serde(flatten)]
    pub tx_type: TransactionTypeBuilder,
    pub fee: Option<FeeBuilder>,
    // Cannot be broadcasted if set to false
    pub broadcast: bool,
    // Returns the TX in HEX format also
    #[serde(default = "default_false_value")]
    pub tx_as_hex: bool
}

#[derive(Serialize, Deserialize)]
pub struct EstimateFeesParams {
    #[serde(flatten)]
    pub tx_type: TransactionTypeBuilder,
}

// :(
fn default_true_value() -> bool {
    true
}

fn default_false_value() -> bool {
    false
}

#[derive(Serialize, Deserialize)]
pub struct ListTransactionsParams {
    pub min_topoheight: Option<u64>,
    pub max_topoheight: Option<u64>,
    /// Receiver address for outgoing txs, and owner/sender for incoming
    pub address: Option<Address>,
    #[serde(default = "default_true_value")]
    pub accept_incoming: bool,
    #[serde(default = "default_true_value")]
    pub accept_outgoing: bool,
    #[serde(default = "default_true_value")]
    pub accept_coinbase: bool,
    #[serde(default = "default_true_value")]
    pub accept_burn: bool,
    // Filter by extra data
    pub query: Option<Query>
}

#[derive(Serialize, Deserialize)]
pub struct TransactionResponse<'a> {
    #[serde(flatten)]
    pub inner: DataHash<'a, Transaction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_as_hex: Option<String>
}

#[derive(Serialize, Deserialize)]
pub struct GetAssetPrecisionParams<'a> {
    pub asset: Cow<'a, Hash>
}

#[derive(Serialize, Deserialize)]
pub struct GetAddressParams {
    // Data to use for creating an integrated address
    // Returned address will contains all the data provided here
    pub integrated_data: Option<DataElement>
}

#[derive(Serialize, Deserialize)]
pub struct SplitAddressParams {
    // address which must be in integrated form
    pub address: Address
}

#[derive(Serialize, Deserialize)]
pub struct SplitAddressResult {
    // Normal address
    pub address: Address,
    // Encoded data from address
    pub integrated_data: DataElement
}

#[derive(Serialize, Deserialize)]
pub struct RescanParams {
    pub until_topoheight: Option<u64>
}

#[derive(Serialize, Deserialize)]
pub struct SetOnlineModeParams {
    pub daemon_address: String
}

#[derive(Serialize, Deserialize)]
pub struct GetBalanceParams {
    pub asset: Option<Hash>
}

#[derive(Serialize, Deserialize)]
pub struct GetTransactionParams {
    pub hash: Hash
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BalanceChanged {
    pub asset: Hash,
    pub balance: u64
}

#[derive(Serialize, Deserialize)]
pub struct GetValueFromKeyParams {
    pub tree: String,
    pub key: DataValue
}

#[derive(Serialize, Deserialize)]
pub struct HasKeyParams {
    pub tree: String,
    pub key: DataValue
}

#[derive(Serialize, Deserialize)]
pub struct GetMatchingKeysParams {
    pub tree: String,
    pub query: Option<Query>
}

#[derive(Serialize, Deserialize)]
pub struct StoreParams {
    pub tree: String,
    pub key: DataValue,
    pub value: DataElement
}

#[derive(Serialize, Deserialize)]
pub struct DeleteParams {
    pub tree: String,
    pub key: DataValue
}

#[derive(Serialize, Deserialize)]
pub struct QueryDBParams {
    pub tree: String,
    pub key: Option<Query>,
    pub value: Option<Query>,
    #[serde(default = "default_false_value")]
    pub return_on_first: bool
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotifyEvent {
    // When a new topoheight is detected by wallet
    // it contains the topoheight (u64) as value
    // It may be lower than the previous one, based on how the DAG reacts
    NewTopoHeight,
    // When a new asset is added to wallet
    // Contains a Hash as value
    NewAsset,
    // When a new transaction is added to wallet
    // Contains TransactionEntry struct as value
    NewTransaction,
    // When a balance is changed
    // Contains a BalanceChanged as value
    BalanceChanged,
    // When a rescan happened on the wallet
    // Contains a topoheight as value to indicate until which topoheight transactions got deleted
    Rescan,
    // When network state changed
    Online,
    // Same here
    Offline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferOut {
    // Destination address
    pub destination: Address,
    // Asset spent
    pub asset: Hash,
    // Plaintext amount
    pub amount: u64,
    // extra data
    pub extra_data: Option<DataElement>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferIn {
    // Asset spent
    pub asset: Hash,
    // Plaintext amount
    pub amount: u64,
    // extra data
    pub extra_data: Option<DataElement>
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryType {
    // Coinbase is only XELIS_ASSET
    Coinbase {
        reward: u64
    },
    Burn {
        asset: Hash,
        amount: u64
    },
    Incoming {
        from: Address,
        transfers: Vec<TransferIn>
    },
    Outgoing {
        transfers: Vec<TransferOut>,
        // Fee paid
        fee: u64,
        // Nonce used
        nonce: u64
    }
}

// This struct is used to represent a transaction entry like in wallet
// But we replace every PublicKey to use Address instead
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionEntry {
    pub hash: Hash,
    pub topoheight: u64,
    #[serde(flatten)]
    pub entry: EntryType,
}