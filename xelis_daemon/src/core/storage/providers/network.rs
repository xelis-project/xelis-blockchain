use xelis_common::{network::Network, serializer::Serializer};
use log::trace;
use crate::core::{error::BlockchainError, storage::{sled::NETWORK, SledStorage}};

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

impl NetworkProvider for SledStorage {
    fn get_network(&self) -> Result<Network, BlockchainError> {
        trace!("get network");
        Ok(self.network)
    }

    fn is_mainnet(&self) -> bool {
        self.network.is_mainnet()
    }

    fn set_network(&mut self, network: &Network) -> Result<(), BlockchainError> {
        trace!("set network to {}", network);
        self.extra.insert(NETWORK, network.to_bytes())?;
        Ok(())
    }

    fn has_network(&self) -> Result<bool, BlockchainError> {
        trace!("has network");
        Ok(self.extra.contains_key(NETWORK)?)
    }
}