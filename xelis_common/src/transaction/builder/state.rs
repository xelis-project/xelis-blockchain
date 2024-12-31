use crate::{
    account::{Nonce, CiphertextCache},
    crypto::{elgamal::Ciphertext, Hash},
    transaction::Reference
};

use super::FeeHelper;

/// If the returned balance and ct do not match, the build function will panic and/or
/// the proof will be invalid.
pub trait AccountState: FeeHelper {

    /// Used to verify if the address is on the same chain
    fn is_mainnet(&self) -> bool;

    /// Get the balance from the source
    fn get_account_balance(&self, asset: &Hash) -> Result<u64, Self::Error>;

    /// Block topoheight at which the transaction is being built
    fn get_reference(&self) -> Reference;

    /// Get the balance ciphertext from the source
    fn get_account_ciphertext(&self, asset: &Hash) -> Result<CiphertextCache, Self::Error>;

    /// Update the balance and the ciphertext
    fn update_account_balance(&mut self, asset: &Hash, new_balance: u64, ciphertext: Ciphertext) -> Result<(), Self::Error>;

    /// Get the nonce of the account
    fn get_nonce(&self) -> Result<Nonce, Self::Error>;

    /// Update account nonce
    fn update_nonce(&mut self, new_nonce: Nonce) -> Result<(), Self::Error>;
}
