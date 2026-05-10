use async_trait::async_trait;
use futures::{Stream, stream};
use log::trace;
use xelis_common::{block::TopoHeight, contract::EventCallbackRegistration, crypto::Hash, serializer::{Serializer, Skip}};
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::{
        ContractEventCallbackProvider,
        VersionedEventCallbackRegistration,
        SledStorage
    }
};

#[async_trait]
impl ContractEventCallbackProvider for SledStorage {
    async fn set_last_contract_event_callback(
        &mut self,
        contract: &Hash,
        event_id: u64,
        listener_contract: &Hash,
        version: VersionedEventCallbackRegistration,
        topoheight: TopoHeight
    ) -> Result<(), BlockchainError> {
        trace!("set last contract event callback for contract {} event {} listener {} at topoheight {}", 
            contract, event_id, listener_contract, topoheight);

        // Store in non-versioned tree for fast lookup (points to topoheight)
        let key = Self::get_event_callback_key(contract, event_id, listener_contract);
        Self::insert_into_disk(self.snapshot.as_mut(), &self.contracts_event_callbacks, &key, topoheight.to_bytes())?;

        // Store in versioned tree for rollback support
        let versioned_key = Self::get_versioned_event_callback_key(topoheight, contract, event_id, listener_contract);
        Self::insert_into_disk(self.snapshot.as_mut(), &self.versioned_contracts_event_callbacks, &versioned_key, version.to_bytes())?;

        Ok(())
    }

    async fn get_event_callback_for_contract_at_maximum_topoheight(
        &self,
        contract: &Hash,
        event_id: u64,
        listener_contract: &Hash,
        max_topoheight: TopoHeight,
    ) -> Result<Option<(TopoHeight, VersionedEventCallbackRegistration)>, BlockchainError> {
        trace!("get event callback for contract {} event {} listener {} at maximum topoheight {}", contract, event_id, listener_contract, max_topoheight);

        let key = Self::get_event_callback_key(contract, event_id, listener_contract);
        let mut topo = self.load_optional_from_disk::<TopoHeight, _>(&self.contracts_event_callbacks, &key)?;
        while let Some(current_topoheight) = topo {
            let versioned_key = Self::get_versioned_event_callback_key(current_topoheight, contract, event_id, listener_contract);
            let version: VersionedEventCallbackRegistration = self.load_from_disk(
                &self.versioned_contracts_event_callbacks,
                &versioned_key,
                DiskContext::ContractEventCallback
            )?;

            if current_topoheight <= max_topoheight {
                return Ok(Some((current_topoheight, version)));
            }

            // Move to the previous topoheight
            topo = version.get_previous_topoheight();
        }

        Ok(None)
    }

    async fn get_event_callbacks_for_event_at_maximum_topoheight<'a>(
        &'a self,
        contract: &'a Hash,
        event_id: u64,
        max_topoheight: TopoHeight,
    ) -> Result<impl Stream<Item = Result<(Hash, TopoHeight, VersionedEventCallbackRegistration), BlockchainError>> + Send + 'a, BlockchainError> {
        trace!("get event callbacks for contract {} event {} at maximum topoheight {}", contract, event_id, max_topoheight);

        // Create prefix: contract + event_id
        let prefix = Self::get_event_callback_prefix(contract, event_id);
        
        // Iterate using the prefix to get all listeners for this event
        Ok(stream::iter(Self::scan_prefix::<Skip<40, Hash>, TopoHeight>(
            self.snapshot.as_ref(),
            &self.contracts_event_callbacks,
            &prefix
        )
        .map(move |res| {
            let (key, last_topoheight) = res?;
            let listener = key.0;

            let mut current_topo = Some(last_topoheight);
            while let Some(topoheight) = current_topo {
                let versioned_key = Self::get_versioned_event_callback_key(topoheight, contract, event_id, &listener);
                let version: VersionedEventCallbackRegistration = self.load_from_disk(
                    &self.versioned_contracts_event_callbacks,
                    &versioned_key,
                    DiskContext::ContractEventCallback
                )?;

                if topoheight <= max_topoheight {
                    return Ok(Some((listener, topoheight, version)));
                }

                // Move to the previous topoheight
                current_topo = version.get_previous_topoheight();
            }

            Ok(None)
        }).filter_map(Result::transpose)))
    }

    async fn get_event_callbacks_available_at_maximum_topoheight<'a>(
        &'a self,
        contract: &'a Hash,
        event_id: u64,
        max_topoheight: TopoHeight,
    ) -> Result<impl Stream<Item = Result<(Hash, EventCallbackRegistration), BlockchainError>> + Send + 'a, BlockchainError> {
        trace!("get event callbacks for contract {} event {} at maximum topoheight {}", contract, event_id, max_topoheight);

        // Create prefix: contract + event_id
        let prefix = Self::get_event_callback_prefix(contract, event_id);
        
        // Iterate using the prefix to get all listeners for this event
        Ok(stream::iter(Self::scan_prefix::<Skip<40, Hash>, TopoHeight>(
            self.snapshot.as_ref(),
            &self.contracts_event_callbacks,
            &prefix
        )
        .map(move |res| {
            let (key, last_topoheight) = res?;
            let listener = key.0;

            let mut current_topo = Some(last_topoheight);
            while let Some(topoheight) = current_topo {
                let versioned_key = Self::get_versioned_event_callback_key(topoheight, contract, event_id, &listener);
                let version: VersionedEventCallbackRegistration = self.load_from_disk(
                    &self.versioned_contracts_event_callbacks,
                    &versioned_key,
                    DiskContext::ContractEventCallback
                )?;

                if topoheight <= max_topoheight {
                    return Ok(match version.take() {
                        Some(callback) => Some((listener, callback)),
                        None => None,
                    });
                }

                // Move to the previous topoheight
                current_topo = version.get_previous_topoheight();
            }

            Ok(None)
        }).filter_map(Result::transpose)))
    }

    async fn get_listeners_for_contract_events<'a>(
        &'a self,
        contract: &'a Hash,
        min_topoheight: TopoHeight,
        max_topoheight: TopoHeight,
    ) -> Result<impl Stream<Item = Result<(u64, Hash, Option<EventCallbackRegistration>), BlockchainError>> + Send + 'a, BlockchainError> {
        trace!("get listeners for contract {} events between topoheight {} and {}", contract, min_topoheight, max_topoheight);

        // Create prefix: contract
        let prefix = contract.as_bytes();
        
        // Iterate using the prefix to get all events for this contract
        Ok(stream::iter(Self::scan_prefix::<Skip<32, (u64, Hash)>, u64>(
            self.snapshot.as_ref(),
            &self.contracts_event_callbacks,
            prefix
        )
        .map(move |res| {
            let (key, last_topoheight) = res?;
            let (event_id, listener) = key.0;

            let mut current_topo = Some(last_topoheight);
            while let Some(topoheight) = current_topo {
                if topoheight < min_topoheight {
                    break; // No need to go further back
                }

                let versioned_key = Self::get_versioned_event_callback_key(topoheight, contract, event_id, &listener);
                let version: VersionedEventCallbackRegistration = self.load_from_disk(
                    &self.versioned_contracts_event_callbacks,
                    &versioned_key,
                    DiskContext::ContractEventCallback
                )?;

                if topoheight <= max_topoheight {
                    return Ok(Some((event_id, listener, version.take())));
                }

                // Move to the previous topoheight
                current_topo = version.get_previous_topoheight();
            }

            Ok(None)
        }).filter_map(Result::transpose)))
    }
}

impl SledStorage {
    // Key: {contract_hash}{event_id}{listener_hash}
    // 32 bytes + 8 bytes + 32 bytes = 72 bytes
    pub fn get_event_callback_key(contract: &Hash, event_id: u64, listener_contract: &Hash) -> [u8; 72] {
        let mut buf = [0; 72];
        buf[0..32].copy_from_slice(contract.as_bytes());
        buf[32..40].copy_from_slice(&event_id.to_be_bytes());
        buf[40..72].copy_from_slice(listener_contract.as_bytes());
        buf
    }

    // Prefix for iteration: {contract_hash}{event_id}
    // 32 bytes + 8 bytes = 40 bytes
    pub fn get_event_callback_prefix(contract: &Hash, event_id: u64) -> [u8; 40] {
        let mut buf = [0; 40];
        buf[0..32].copy_from_slice(contract.as_bytes());
        buf[32..40].copy_from_slice(&event_id.to_be_bytes());
        buf
    }

    // Versioned key: {topoheight}{contract_hash}{event_id}{listener_hash}
    // 8 bytes + 32 bytes + 8 bytes + 32 bytes = 80 bytes
    pub fn get_versioned_event_callback_key(topoheight: TopoHeight, contract: &Hash, event_id: u64, listener_contract: &Hash) -> [u8; 80] {
        let mut buf = [0; 80];
        buf[0..8].copy_from_slice(&topoheight.to_be_bytes());
        buf[8..40].copy_from_slice(contract.as_bytes());
        buf[40..48].copy_from_slice(&event_id.to_be_bytes());
        buf[48..80].copy_from_slice(listener_contract.as_bytes());
        buf
    }
}
