mod data;
mod balance;
mod scheduled_execution;

use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use crate::core::error::BlockchainError;

pub use data::*;
pub use balance::*;
pub use scheduled_execution::VersionedScheduledExecutionsProvider;

#[async_trait]
pub trait VersionedContractProvider: VersionedContractDataProvider + VersionedContractBalanceProvider + VersionedScheduledExecutionsProvider {
    // delete versioned contracts at topoheight
    async fn delete_versioned_contracts_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // delete versioned contracts above topoheight
    async fn delete_versioned_contracts_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // delete versioned contracts below topoheight
    async fn delete_versioned_contracts_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError>;
}