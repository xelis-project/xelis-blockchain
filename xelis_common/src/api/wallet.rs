use serde::{Deserialize, Serialize};

use crate::{transaction::{TransactionType, Transaction}, crypto::{key::PublicKey, hash::Hash}};

use super::{DataHash, DataType};


#[derive(Serialize, Deserialize)]
pub enum FeeBuilder {
    Multiplier(f64), // calculate tx fees based on its size and multiply by this value
    Value(u64) // set a direct value of how much fees you want to pay
}

#[derive(Serialize, Deserialize)]
pub struct BuildTransactionParams {
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
    pub address: Option<PublicKey>,
    #[serde(default = "default_filter_value")]
    pub accept_incoming: bool,
    #[serde(default = "default_filter_value")]
    pub accept_outgoing: bool,
    #[serde(default = "default_filter_value")]
    pub accept_coinbase: bool,
    #[serde(default = "default_filter_value")]
    pub accept_burn: bool,
}

#[derive(Serialize, Deserialize)]
pub struct TransactionResponse<'a> {
    #[serde(flatten)]
    pub inner: DataHash<'a, Transaction>,
}

#[derive(Serialize, Deserialize)]
pub struct GetAddressParams {
    pub data: Option<DataType>
}

#[derive(Serialize, Deserialize)]
pub struct GetBalanceParams {
    pub asset: Option<Hash>
}

#[derive(Serialize, Deserialize)]
pub struct GetTransactionParams {
    pub hash: Hash
}