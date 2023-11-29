use std::borrow::Cow;

use serde::{Deserialize, Serialize};

use crate::{transaction::{TransactionType, Transaction}, crypto::{hash::Hash, address::Address}};

use super::{DataHash, DataElement, DataValue, DataType};


#[derive(Serialize, Deserialize)]
pub enum FeeBuilder {
    Multiplier(f64), // calculate tx fees based on its size and multiply by this value
    Value(u64) // set a direct value of how much fees you want to pay
}

#[derive(Serialize, Deserialize)]
pub struct BuildTransactionParams {
    #[serde(flatten)]
    pub tx_type: TransactionType,    
    pub fee: Option<FeeBuilder>,
    pub broadcast: bool
}

// :(
fn default_filter_value() -> bool {
    true
}

#[derive(Serialize, Deserialize)]
pub struct ListTransactionsParams {
    pub min_topoheight: Option<u64>,
    pub max_topoheight: Option<u64>,
    /// Receiver address for outgoing txs, and owner/sender for incoming
    pub address: Option<Address>,
    #[serde(default = "default_filter_value")]
    pub accept_incoming: bool,
    #[serde(default = "default_filter_value")]
    pub accept_outgoing: bool,
    #[serde(default = "default_filter_value")]
    pub accept_coinbase: bool,
    #[serde(default = "default_filter_value")]
    pub accept_burn: bool,
    // Filter by extra data
    pub query: Option<QuerySearcher>
}

// Structure to allow for searching a precise key/value pair in extra data
// Value is nullable to allow for searching only by key also
#[derive(Serialize, Deserialize)]
pub enum QuerySearcher {
    KeyValue { key: DataValue, value: Option<DataValue> },
    KeyType { key: DataValue, kind: DataType }
}

#[derive(Serialize, Deserialize)]
pub struct TransactionResponse<'a> {
    #[serde(flatten)]
    pub inner: DataHash<'a, Transaction>,
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
pub struct GetBalanceParams {
    pub asset: Option<Hash>
}

#[derive(Serialize, Deserialize)]
pub struct GetTransactionParams {
    pub hash: Hash
}

#[derive(Serialize, Deserialize)]
pub struct BalanceChanged<'a> {
    pub asset: Cow<'a, Hash>,
    pub balance: u64
}

#[derive(Serialize, Deserialize)]
pub struct GetCustomDataParams {
    pub tree: String,
    pub key: DataValue
}

#[derive(Serialize, Deserialize)]
pub struct GetCustomTreeKeysParams {
    pub tree: String
}

#[derive(Serialize, Deserialize)]
pub struct SetCustomDataParams {
    pub tree: String,
    pub key: DataValue,
    pub value: DataElement
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NotifyEvent {
    // When a new block is detected by wallet
    // it contains Block struct as value
    // NewBlock,
    // When a a get_info request is made
    // and we receive a different topoheight than previous one
    NewChainInfo,
    // When a new asset is added to wallet
    // Contains a Hash as value
    NewAsset,
    // When a new transaction is added to wallet
    // Contains TransactionEntry struct as value
    NewTransaction,
    // When a balance is changed
    // Contains a BalanceChanged as value
    BalanceChanged,
}