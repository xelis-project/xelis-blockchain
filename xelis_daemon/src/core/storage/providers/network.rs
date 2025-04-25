use xelis_common::network::Network;
use crate::core::error::BlockchainError;

pub trait NetworkProvider {
    // Get the network from cache
    fn get_network(&self) -> Result<Network, BlockchainError>;

    // Is the network mainnet
    fn is_mainnet(&self) -> bool;

    // Set the network in the storage
    fn set_network(&mut self, network: &Network) -> Result<(), BlockchainError>;

    // Do we have a network stored in DB ?
    fn has_network(&self) -> Result<bool, BlockchainError>;
}