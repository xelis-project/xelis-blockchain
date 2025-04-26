use serde::{Deserialize, Serialize};

use crate::crypto::elgamal::CompressedPublicKey;

#[derive(Serialize, Deserialize, Clone, Debug, Copy)]
#[serde(rename_all = "snake_case")]
pub enum FeeBuilder {
    // calculate tx fees based on its size and multiply by this value
    Multiplier(f64),
    // set a direct value of how much fees you want to pay exactly
    Value(u64),
    // how much we want to pay above the calculated/needed fees.
    Boost(u64)
}

impl Default for FeeBuilder {
    fn default() -> Self {
        FeeBuilder::Boost(0)
    }
}

pub trait FeeHelper {
    type Error;

    /// Get the fee multiplier from wallet if wanted
    fn get_fee_multiplier(&self) -> f64 {
        1f64
    }

    /// Verify if the account exists or if we should pay more fees for account creation
    fn account_exists(&self, account: &CompressedPublicKey) -> Result<bool, Self::Error>;
}
