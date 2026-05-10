use pooled_arc::PooledArc;
use async_trait::async_trait;
use anyhow::Context;
use futures::stream;
use xelis_common::{
    block::TopoHeight,
    crypto::Hash,
};
use crate::core::storage::VersionedContractData;
use xelis_vm::ValueCell;
use futures::Stream;
use crate::core::{
    error::BlockchainError,
    storage::ContractDataProvider,
};
use super::super::super::MemoryStorage;

#[async_trait]
impl ContractDataProvider for MemoryStorage {
    async fn set_last_contract_data_to(&mut self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight, version: &VersionedContractData) -> Result<(), BlockchainError> {
        let shared = PooledArc::from_ref(contract);
        self.contracts.entry(shared)
            .or_default()
            .data
            .entry(key.clone())
            .or_default()
            .insert(topoheight, version.clone());

        Ok(())
    }

    async fn get_last_topoheight_for_contract_data(&self, contract: &Hash, key: &ValueCell) -> Result<Option<TopoHeight>, BlockchainError> {
        Ok(self.contracts.get(contract)
            .and_then(|entry| entry.data.get(key))
            .and_then(|data_map| data_map.keys().max().copied())
        )
    }

    async fn get_contract_data_at_exact_topoheight_for<'a>(&self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight) -> Result<VersionedContractData, BlockchainError> {
        self.contracts.get(contract)
            .and_then(|entry| entry.data.get(key))
            .and_then(|data_map| data_map.get(&topoheight))
            .cloned()
            .with_context(|| format!("Contract data not found for contract {:?}, key {:?}, topoheight {}", contract, key, topoheight))
            .map_err(|e| e.into())
    }

    async fn get_contract_data_at_maximum_topoheight_for<'a>(&self, contract: &Hash, key: &ValueCell, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedContractData)>, BlockchainError> {
        Ok(self.contracts.get(contract)
            .and_then(|entry| entry.data.get(key))
            .and_then(|data| data.range(..=maximum_topoheight).next_back())
            .map(|(t, d)| (*t, d.clone()))
        )
    }

    async fn get_contract_data_topoheight_at_maximum_topoheight_for<'a>(&self, contract: &Hash, key: &ValueCell, maximum_topoheight: TopoHeight) -> Result<Option<TopoHeight>, BlockchainError> {
        Ok(self.contracts.get(contract)
            .and_then(|entry| entry.data.get(key))
            .and_then(|data| data.range(..=maximum_topoheight).next_back())
            .map(|(t, _)| *t)
        )
    }

    async fn has_contract_data_at_exact_topoheight(&self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        Ok(self.contracts.get(contract)
            .and_then(|entry| entry.data.get(key))
            .map_or(false, |data_map| data_map.contains_key(&topoheight))
        )
    }

    async fn get_contract_data_entries_at_maximum_topoheight<'a>(&'a self, contract: &'a Hash, topoheight: TopoHeight) -> Result<impl Stream<Item = Result<(ValueCell, ValueCell), BlockchainError>> + Send + 'a, BlockchainError> {
        let entries = self.contracts.get(contract)
            .with_context(|| format!("Contract data entries not found for contract {:?}, topoheight {}", contract, topoheight))?
            .data
            .iter()
            .filter_map(move |(key, data_map)| data_map.range(..=topoheight)
                .next_back()
                .and_then(|(_, data)| data.get()
                    .as_ref()
                    .map(|value| (key.clone(), value.clone()))
                )
            )
            .map(Ok);

        Ok(stream::iter(entries))
    }
}
