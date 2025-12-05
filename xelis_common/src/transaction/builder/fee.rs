use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::crypto::elgamal::CompressedPublicKey;

#[derive(Serialize, Deserialize, Clone, Debug, Copy, Default, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExtraFeeMode {
    #[default]
    None,
    // how much we want to pay above the calculated/required fees.
    // This is useful to have more chance to get included first
    Tip(u64),
    // multiply the calculated fee,
    Multiplier(f64),
}

#[derive(Serialize, Deserialize, Clone, Debug, Copy, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FeeBuilder {
    // Fixed fee amount to use for the TX
    Fixed(u64),
    // Determined either by the wallet, or by the given constraints
    Extra(ExtraFeeMode)
    // TODO: support a "maximum fee" for future
}

impl Default for FeeBuilder {
    fn default() -> Self {
        FeeBuilder::Extra(ExtraFeeMode::None)
    }
}

pub trait FeeHelper {
    type Error;

    /// Get the fee multiplier from wallet if wanted
    fn get_fee_multiplier(&self) -> f64 {
        1f64
    }

    // Get the default base fee per KB
    // By default, returns None to use the minimal required
    fn get_base_fee(&self) -> Option<u64> {
        None
    }

    // Get the maximum fee to pay in case of higher base fee
    // By default, returns the same as TX fee
    fn get_max_fee(&self, fee: u64) -> u64 {
        fee
    }

    /// Verify if the account exists or if we should pay more fees for account creation
    fn account_exists(&self, account: &CompressedPublicKey) -> Result<bool, Self::Error>;
}
