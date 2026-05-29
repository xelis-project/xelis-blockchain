use async_trait::async_trait;
use futures::Stream;
use xelis_common::{block::TopoHeight, crypto::Hash, contract::EventCallbackRegistration, versioned::Versioned};

use crate::core::error::BlockchainError;

pub type VersionedEventCallbackRegistration = Versioned<Option<EventCallbackRegistration>>;

#[async_trait]
pub trait ContractEventCallbackProvider {
    // Register a listener for an event
    // contract: the contract that emits the event
    // event_id: the event identifier to listen to
    // listener_contract: the contract that will receive the callback
    // version: the event callback registration data (chunk_id, max_gas)
    // topoheight: the topoheight at which this registration is made
    async fn set_last_contract_event_callback(
        &mut self,
        contract: &Hash,
        event_id: u64,
        listener_contract: &Hash,
        version: VersionedEventCallbackRegistration,
        topoheight: TopoHeight
    ) -> Result<(), BlockchainError>;

    /// Get the latest version for a specific contract event listener
    /// at or below the specified maximum topoheight
    async fn get_event_callback_for_contract_at_maximum_topoheight(
        &self,
        contract: &Hash,
        event_id: u64,
        listener_contract: &Hash,
        max_topoheight: TopoHeight,
    ) -> Result<Option<(TopoHeight, VersionedEventCallbackRegistration)>, BlockchainError>;

    // Get all latest versions for a specific contract event 
    // Returns (listener_contract, version) for each latest version
    async fn get_event_callbacks_for_event_at_maximum_topoheight<'a>(
        &'a self,
        contract: &'a Hash,
        event_id: u64,
        max_topoheight: TopoHeight,
    ) -> Result<impl Stream<Item = Result<(Hash, TopoHeight, VersionedEventCallbackRegistration), BlockchainError>> + Send + 'a, BlockchainError>;

    // Get all latest versions for a specific contract event 
    // Returns (listener_contract, version) for each latest version
    async fn get_event_callbacks_available_at_maximum_topoheight<'a>(
        &'a self,
        contract: &'a Hash,
        event_id: u64,
        max_topoheight: TopoHeight,
    ) -> Result<impl Stream<Item = Result<(Hash, EventCallbackRegistration), BlockchainError>> + Send + 'a, BlockchainError>;

    // Get all available listeners for a contract at a maximum topoheight
    // Returns (event_id, listener_contract, version) for each latest version
    // version is None if the listener has been consumed and is no longer available
    async fn get_listeners_for_contract_events<'a>(
        &'a self,
        contract: &'a Hash,
        min_topoheight: TopoHeight,
        max_topoheight: TopoHeight,
    ) -> Result<impl Stream<Item = Result<(u64, Hash, Option<EventCallbackRegistration>), BlockchainError>> + Send + 'a, BlockchainError>;
}