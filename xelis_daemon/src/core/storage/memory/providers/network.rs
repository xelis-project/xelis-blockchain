use xelis_common::network::Network;
use crate::core::{
    error::BlockchainError,
    storage::NetworkProvider,
};
use super::super::MemoryStorage;

impl NetworkProvider for MemoryStorage {
    fn get_network(&self) -> Result<Network, BlockchainError> {
        Ok(self.network)
    }

    fn is_mainnet(&self) -> bool {
        self.network.is_mainnet()
    }

    fn set_network(&mut self, network: &Network) -> Result<(), BlockchainError> {
        self.network = *network;
        Ok(())
    }

    fn has_network(&self) -> Result<bool, BlockchainError> {
        Ok(true)
    }
}
