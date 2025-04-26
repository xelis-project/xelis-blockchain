use xelis_common::network::Network;
use log::trace;
use crate::core::{
    error::BlockchainError,
    storage::{Column, NetworkProvider, RocksStorage}
};

impl NetworkProvider for RocksStorage {
    fn get_network(&self) -> Result<Network, BlockchainError> {
        trace!("get network");
        Ok(self.network)
    }

    fn is_mainnet(&self) -> bool {
        self.network.is_mainnet()
    }

    fn set_network(&mut self, network: &Network) -> Result<(), BlockchainError> {
        trace!("set network to {}", network);
        self.insert_into_disk(Column::Common, b"network", network)
    }

    fn has_network(&self) -> Result<bool, BlockchainError> {
        trace!("has network");
        self.contains_data(Column::Common, b"network")
    }
}