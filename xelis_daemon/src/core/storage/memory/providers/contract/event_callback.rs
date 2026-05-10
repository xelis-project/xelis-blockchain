use futures::{Stream, stream};
use log::trace;
use pooled_arc::PooledArc;
use async_trait::async_trait;
use xelis_common::{
    block::TopoHeight,
    contract::EventCallbackRegistration,
    crypto::Hash,
};
use crate::core::storage::VersionedEventCallbackRegistration;
use crate::core::{
    error::BlockchainError,
    storage::ContractEventCallbackProvider,
};
use super::super::super::MemoryStorage;

#[async_trait]
impl ContractEventCallbackProvider for MemoryStorage {
    async fn set_last_contract_event_callback(
        &mut self,
        contract: &Hash,
        event_id: u64,
        listener_contract: &Hash,
        version: VersionedEventCallbackRegistration,
        topoheight: TopoHeight,
    ) -> Result<(), BlockchainError> {
        self.contracts.get_mut(contract)
            .ok_or_else(|| BlockchainError::ContractNotFound(contract.clone()))?
            .events_callbacks
            .entry(event_id)
            .or_default()
            .entry(PooledArc::from_ref(listener_contract))
            .or_default()
            .insert(topoheight, version.clone());

        Ok(())
    }

    async fn get_event_callback_for_contract_at_maximum_topoheight(
        &self,
        contract: &Hash,
        event_id: u64,
        listener_contract: &Hash,
        max_topoheight: TopoHeight,
    ) -> Result<Option<(TopoHeight, VersionedEventCallbackRegistration)>, BlockchainError> {
        let listener = PooledArc::from_ref(listener_contract);
        Ok(self.contracts.get(contract)
            .and_then(|data| data.events_callbacks.get(&event_id))
            .and_then(|m| m.get(&listener))
            .and_then(|versions| versions.range(..=max_topoheight).next_back())
            .map(|(&topo, ver)| (topo, ver.clone()))
        )
    }

    async fn get_event_callbacks_for_event_at_maximum_topoheight<'a>(
        &'a self,
        contract: &'a Hash,
        event_id: u64,
        max_topoheight: TopoHeight,
    ) -> Result<impl Stream<Item = Result<(Hash, TopoHeight, VersionedEventCallbackRegistration), BlockchainError>> + Send + 'a, BlockchainError> {
        Ok(stream::iter(self.contracts.get(contract)
            .into_iter()
            .flat_map(move |data| data.events_callbacks.get(&event_id).into_iter()
                .flat_map(move |listeners| listeners.iter()
                    .filter_map(move |(listener, versions)| {
                        versions.range(..=max_topoheight).next_back().map(|(&topo, ver)| {
                            Ok((listener.as_ref().clone(), topo, ver.clone()))
                        })
                    })
                )
            )
        ))
    }

    async fn get_event_callbacks_available_at_maximum_topoheight<'a>(
        &'a self,
        contract: &'a Hash,
        event_id: u64,
        max_topoheight: TopoHeight,
    ) -> Result<impl Stream<Item = Result<(Hash, EventCallbackRegistration), BlockchainError>> + Send + 'a, BlockchainError> {
        Ok(stream::iter(self.contracts.get(contract)
            .into_iter()
            .flat_map(move |data| data.events_callbacks.get(&event_id).into_iter()
                .flat_map(move |listeners| listeners.iter()
                    .filter_map(move |(listener, versions)| {
                        versions.range(..=max_topoheight).next_back().and_then(|(_, version)| {
                            version.get().as_ref().map(|reg| Ok((listener.as_ref().clone(), reg.clone())))
                        })
                    })
                )
            )
        ))
    }

    /// Get all available listeners for a contract at a maximum topoheight
    async fn get_listeners_for_contract_events<'a>(
        &'a self,
        contract: &'a Hash,
        min_topoheight: TopoHeight,
        max_topoheight: TopoHeight,
    ) -> Result<impl Stream<Item = Result<(u64, Hash, Option<EventCallbackRegistration>), BlockchainError>> + Send + 'a, BlockchainError> {
        trace!("get listeners for contract {} events between topoheights {} and {}", contract, min_topoheight, max_topoheight);

        Ok(stream::iter(self.contracts.get(contract)
            .into_iter()
            .flat_map(move |data| data.events_callbacks.iter()
                .flat_map(move |(&event_id, listeners)| listeners.iter()
                    .filter_map(move |(listener, versions)| {
                        versions.range(min_topoheight..=max_topoheight).next_back().map(|(_, version)| {
                            Ok((event_id, listener.as_ref().clone(), version.get().clone()))
                        })
                    })
                )
            )
        ))
    }
}
