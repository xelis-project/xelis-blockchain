use async_trait::async_trait;
use futures::{Stream, stream};
use log::trace;
use xelis_common::{block::TopoHeight, contract::EventCallbackRegistration, crypto::Hash};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::{Column, ContractId, IteratorMode},
        snapshot::Direction,
        ContractEventCallbackProvider,
        VersionedEventCallbackRegistration,
        RocksStorage
    }
};

#[async_trait]
impl ContractEventCallbackProvider for RocksStorage {
    async fn set_last_contract_event_callback(
        &mut self,
        contract: &Hash,
        event_id: u64,
        listener_contract: &Hash,
        version: VersionedEventCallbackRegistration,
        topoheight: TopoHeight
    ) -> Result<(), BlockchainError> {
        trace!("set last contract event callback for contract {} event {} listener {} at topoheight {}", contract, event_id, listener_contract, topoheight);

        let contract_id = self.get_contract_id(contract)?;
        let listener_id = self.get_contract_id(listener_contract)?;

        // Store in non-versioned column for fast lookup (points to topoheight)
        let key = Self::get_event_callback_key(contract_id, event_id, listener_id);
        self.insert_into_disk(Column::ContractEventCallbacks, &key, &topoheight)?;

        // Store in versioned column for rollback support
        let versioned_key = Self::get_versioned_event_callback_key(topoheight, contract_id, event_id, listener_id);
        self.insert_into_disk(Column::VersionedContractEventCallbacks, &versioned_key, &version)
    }

    async fn get_event_callback_for_contract_at_maximum_topoheight(
        &self,
        contract: &Hash,
        event_id: u64,
        listener_contract: &Hash,
        max_topoheight: TopoHeight,
    ) -> Result<Option<(TopoHeight, VersionedEventCallbackRegistration)>, BlockchainError> {
        trace!("get event callback for contract {} event {} listener {} at maximum topoheight {}", contract, event_id, listener_contract, max_topoheight);

        self.run_blocking(|| {
            let Some(contract_id) = self.get_optional_contract_id(contract)? else {
                return Ok(None);
            };
            let Some(listener_id) = self.get_optional_contract_id(listener_contract)? else {
                return Ok(None);
            };

            let versioned_key = Self::get_versioned_event_callback_key(max_topoheight, contract_id, event_id, listener_id);
            let mut topo = if self.contains_data(Column::VersionedContractEventCallbacks, &versioned_key)? {
                Some(max_topoheight)
            } else {
                // Create key: {contract_id}{event_id}{listener_id}
                let key = Self::get_event_callback_key(contract_id, event_id, listener_id);
                // If the versioned key doesn't exist, we can check the non-versioned column for the last topoheight
                self.load_optional_from_disk(Column::ContractEventCallbacks, &key)?
            };

            while let Some(current_topoheight) = topo {
                let versioned_key = Self::get_versioned_event_callback_key(current_topoheight, contract_id, event_id, listener_id);
                let version: VersionedEventCallbackRegistration = self.load_from_disk(Column::VersionedContractEventCallbacks, &versioned_key)?;
                if current_topoheight <= max_topoheight {
                    return Ok(Some((current_topoheight, version)))
                }

                topo = version.get_previous_topoheight();
            }

            Ok(None)
        })
    }

    async fn get_event_callbacks_for_event_at_maximum_topoheight<'a>(
        &'a self,
        contract: &'a Hash,
        event_id: u64,
        max_topoheight: TopoHeight,
    ) -> Result<impl Stream<Item = Result<(Hash, TopoHeight, VersionedEventCallbackRegistration), BlockchainError>> + Send + 'a, BlockchainError> {
        trace!("get event callbacks for contract {} event {} at maximum topoheight {}", contract, event_id, max_topoheight);

        let contract_id = self.get_contract_id(contract)?;
        // Create prefix: contract_id + event_id
        let prefix = Self::get_event_callback_prefix(contract_id, event_id);

        // Iterate using the prefix to get all listeners for this event
        self.iter::<(ContractId, u64, ContractId), TopoHeight>(Column::ContractEventCallbacks, IteratorMode::WithPrefix(&prefix, Direction::Forward))
            .map(move |iter| iter.map(move |res| {
                let ((_, _, listener_id), last_topoheight) = res?;

                let versioned_key = Self::get_versioned_event_callback_key(max_topoheight, contract_id, event_id, listener_id);
                let mut topo = if self.contains_data(Column::VersionedContractEventCallbacks, &versioned_key)? {
                    Some(max_topoheight)
                } else {
                    Some(last_topoheight)
                };

                while let Some(current_topoheight) = topo {
                    let versioned_key = Self::get_versioned_event_callback_key(current_topoheight, contract_id, event_id, listener_id);
                    let version: VersionedEventCallbackRegistration = self.load_from_disk(Column::VersionedContractEventCallbacks, &versioned_key)?;
                    if current_topoheight <= max_topoheight {
                        let listener = self.get_contract_from_id(listener_id)?;
                        return Ok(Some((listener, current_topoheight, version)))
                    }

                    topo = version.get_previous_topoheight();
                }

                Ok(None)
            }).filter_map(Result::transpose))
            .map(stream::iter)
    }

    async fn get_event_callbacks_available_at_maximum_topoheight<'a>(
        &'a self,
        contract: &'a Hash,
        event_id: u64,
        max_topoheight: TopoHeight,
    ) -> Result<impl Stream<Item = Result<(Hash, EventCallbackRegistration), BlockchainError>> + Send + 'a, BlockchainError> {
        trace!("get event callbacks for contract {} event {} at maximum topoheight {}", contract, event_id, max_topoheight);

        let contract_id = self.get_contract_id(contract)?;
        // Create prefix: contract_id + event_id
        let prefix = Self::get_event_callback_prefix(contract_id, event_id);

        // Iterate using the prefix to get all listeners for this event
        self.iter::<(ContractId, u64, ContractId), TopoHeight>(Column::ContractEventCallbacks, IteratorMode::WithPrefix(&prefix, Direction::Forward))
            .map(move |iter| iter.map(move |res| {
                let ((_, _, listener_id), last_topoheight) = res?;

                let versioned_key = Self::get_versioned_event_callback_key(max_topoheight, contract_id, event_id, listener_id);
                let mut topo = if self.contains_data(Column::VersionedContractEventCallbacks, &versioned_key)? {
                    Some(max_topoheight)
                } else {
                    Some(last_topoheight)
                };

                while let Some(current_topoheight) = topo {
                    let versioned_key = Self::get_versioned_event_callback_key(current_topoheight, contract_id, event_id, listener_id);
                    let version: VersionedEventCallbackRegistration = self.load_from_disk(Column::VersionedContractEventCallbacks, &versioned_key)?;
                    if current_topoheight <= max_topoheight {
                        return Ok(match version.take() {
                            Some(callback) => {
                                let listener = self.get_contract_from_id(listener_id)?;
                                Some((listener, callback))
                            }
                            None => None,
                        })
                    }

                    topo = version.get_previous_topoheight();
                }

                Ok(None)
            }).filter_map(Result::transpose))
            .map(stream::iter)
    }

    async fn get_listeners_for_contract_events<'a>(
        &'a self,
        contract: &'a Hash,
        min_topoheight: TopoHeight,
        max_topoheight: TopoHeight,
    ) -> Result<impl Stream<Item = Result<(u64, Hash, Option<EventCallbackRegistration>), BlockchainError>> + Send + 'a, BlockchainError> {
        trace!("get listeners for contract {} events between topoheight {} and {}", contract, min_topoheight, max_topoheight);

        let contract_id = self.get_contract_id(contract)?;
        // Create prefix: contract_id
        let prefix = contract_id.to_be_bytes();

        self.iter::<(ContractId, u64, u64), TopoHeight>(Column::ContractEventCallbacks, IteratorMode::From(&prefix, Direction::Forward))
            .map(move |iter| iter
                .take_while(move |res| res.as_ref().map_or(false, |((cid, _, _), _)| *cid == contract_id))
                .map(move |res| {
                let ((_, event_id, listener_id), last_topoheight) = res?;

                let mut topo = Some(last_topoheight);
                while let Some(current_topoheight) = topo {
                    if current_topoheight < min_topoheight {
                        break;
                    }

                    let versioned_key = Self::get_versioned_event_callback_key(current_topoheight, contract_id, event_id, listener_id);
                    let version: VersionedEventCallbackRegistration = self.load_from_disk(Column::VersionedContractEventCallbacks, &versioned_key)?;
                    if current_topoheight <= max_topoheight {
                        let listener = self.get_contract_from_id(listener_id)?;
                        return Ok(Some((event_id, listener, version.take())))
                    }

                    topo = version.get_previous_topoheight();
                }

                Ok(None)
            }).filter_map(Result::transpose))
            .map(stream::iter)
    }
}

impl RocksStorage {
    // Key: {contract_id}{event_id}{listener_id}
    pub fn get_event_callback_key(contract_id: ContractId, event_id: u64, listener_id: ContractId) -> [u8; 24] {
        let mut buf = [0; 24];
        buf[0..8].copy_from_slice(&contract_id.to_be_bytes());
        buf[8..16].copy_from_slice(&event_id.to_be_bytes());
        buf[16..24].copy_from_slice(&listener_id.to_be_bytes());
        buf
    }

    // Prefix for iteration: {contract_id}{event_id}
    pub fn get_event_callback_prefix(contract_id: ContractId, event_id: u64) -> [u8; 16] {
        let mut buf = [0; 16];
        buf[0..8].copy_from_slice(&contract_id.to_be_bytes());
        buf[8..16].copy_from_slice(&event_id.to_be_bytes());
        buf
    }

    // Versioned key: {topoheight}{contract_id}{event_id}{listener_id}
    pub fn get_versioned_event_callback_key(topoheight: TopoHeight, contract_id: ContractId, event_id: u64, listener_id: ContractId) -> [u8; 32] {
        let mut buf = [0; 32];
        buf[0..8].copy_from_slice(&topoheight.to_be_bytes());
        buf[8..16].copy_from_slice(&contract_id.to_be_bytes());
        buf[16..24].copy_from_slice(&event_id.to_be_bytes());
        buf[24..32].copy_from_slice(&listener_id.to_be_bytes());
        buf
    }
}
