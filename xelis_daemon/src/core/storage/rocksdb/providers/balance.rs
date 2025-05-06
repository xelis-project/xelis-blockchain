use async_trait::async_trait;
use xelis_common::{
    account::{
        AccountSummary,
        Balance,
        VersionedBalance
    },
    block::TopoHeight,
    crypto::{
        Hash,
        PublicKey
    },
};
use crate::core::{error::BlockchainError, storage::{BalanceProvider, RocksStorage}};

#[async_trait]
impl BalanceProvider for RocksStorage {
    // Check if a balance exists for asset and key
    async fn has_balance_for(&self, key: &PublicKey, asset: &Hash) -> Result<bool, BlockchainError> {
        todo!()
    }

    // Check if a balance exists for asset and key at specific topoheight
    async fn has_balance_at_exact_topoheight(&self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        todo!()
    }

    // Get the balance at a specific topoheight for asset and key
    async fn get_balance_at_exact_topoheight(&self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight) -> Result<VersionedBalance, BlockchainError> {
        todo!()
    }

    // Get the balance under or equal topoheight requested for asset and key
    async fn get_balance_at_maximum_topoheight(&self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedBalance)>, BlockchainError> {
        todo!()
    }

    // Get the last topoheight that the account has a balance
    async fn get_last_topoheight_for_balance(&self, key: &PublicKey, asset: &Hash) -> Result<TopoHeight, BlockchainError> {
        todo!()
    }

    // Get a new versioned balance of the account, this is based on the requested topoheight
    // And is returning the versioned balance at maximum topoheight
    // Versioned balance as the previous topoheight set also based on which height it is set
    // So, if we are at topoheight 50 and we have a balance at topoheight 40, the previous topoheight will be 40
    // But also if we have a balance at topoheight 50, the previous topoheight will also be 50
    // This must be called only to create a new versioned balance for the next topoheight as it's keeping changes from the balance at same topo
    // Bool return type is true if the balance is new (no previous balance found)
    async fn get_new_versioned_balance(&self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight) -> Result<(VersionedBalance, bool), BlockchainError> {
        todo!()
    }

    // Search the highest balance where we have a outgoing TX
    async fn get_output_balance_at_maximum_topoheight(&self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedBalance)>, BlockchainError> {
        todo!()
    }

    // Search the highest balance where we have a spending
    // To short-circuit the search, we stop if we go below the reference topoheight
    async fn get_output_balance_in_range(&self, key: &PublicKey, asset: &Hash, min_topoheight: TopoHeight, max_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedBalance)>, BlockchainError> {
        todo!()
    }

    // Get the last balance of the account, this is based on the last topoheight (pointer) available
    async fn get_last_balance(&self, key: &PublicKey, asset: &Hash) -> Result<(TopoHeight, VersionedBalance), BlockchainError> {
        todo!()
    }

    // Get the asset versioned balances for multiple keys
    async fn get_versioned_balances<'a, I: Iterator<Item = &'a PublicKey> + Send>(&self, asset: &Hash, keys: I, maximum_topoheight: TopoHeight) -> Result<Vec<Option<VersionedBalance>>, BlockchainError> {
        todo!()
    }

    // Set the last topoheight for this asset and key to the requested topoheight
    fn set_last_topoheight_for_balance(&mut self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        todo!()
    }

    // Set the last balance of the account, update the last topoheight pointer for asset and key
    // This is same as `set_last_topoheight_for_balance` but will also update the versioned balance
    async fn set_last_balance_to(&mut self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight, version: &VersionedBalance) -> Result<(), BlockchainError> {
        todo!()
    }

    // Set the balance at specific topoheight for asset and key
    async fn set_balance_at_topoheight(&mut self, asset: &Hash, topoheight: TopoHeight, key: &PublicKey, balance: &VersionedBalance) -> Result<(), BlockchainError> {
        todo!()
    }

    // Delete the balance at specific topoheight for asset and key
    async fn delete_balance_at_topoheight(&mut self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight) -> Result<VersionedBalance, BlockchainError> {
        todo!()
    }

    // Delete the last topoheight for asset and key
    // This will only remove the pointer, not the version itself
    fn delete_last_topoheight_for_balance(&mut self, key: &PublicKey, asset: &Hash) -> Result<(), BlockchainError> {
        todo!()
    }

    // Get the account summary for a key and asset on the specified topoheight range
    // If None is returned, that means there was no changes that occured in the specified topoheight range
    async fn get_account_summary_for(&self, key: &PublicKey, asset: &Hash, min_topoheight: TopoHeight, max_topoheight: TopoHeight) -> Result<Option<AccountSummary>, BlockchainError> {
        todo!()
    }

    // Get the spendable balances for a key and asset on the specified topoheight (exclusive) range
    // Maximum 1024 entries per Vec<Balance>, Option<TopoHeight> is Some if we have others previous versions available and Vec is full.
    // It will stop at the first output balance found without including it
    async fn get_spendable_balances_for(&self, key: &PublicKey, asset: &Hash, min_topoheight: TopoHeight, max_topoheight: TopoHeight) -> Result<(Vec<Balance>, Option<TopoHeight>), BlockchainError> {
        todo!()
    }
}