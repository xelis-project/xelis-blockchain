use serde::{Deserialize, Serialize};

use crate::transaction::{TransactionType, Transaction};

use super::DataHash;


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

#[derive(Serialize, Deserialize)]
pub struct TransactionResponse<'a> {
    pub tx: DataHash<'a, Transaction>,
}