use async_trait::async_trait;
use futures::{stream, Stream, StreamExt};
use log::trace;
use xelis_vm::ValueCell;
use xelis_common::{
    block::TopoHeight,
    crypto::Hash,
    serializer::Serializer,
};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::{Column, ContractDataId, ContractId, IteratorMode},
        snapshot::Direction,
        ContractDataProvider,
        RocksStorage,
        VersionedContractData
    }
};

#[async_trait]
impl ContractDataProvider for RocksStorage {
    // Set a contract data
    async fn set_last_contract_data_to(&mut self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight, version: &VersionedContractData) -> Result<(), BlockchainError> {
        trace!("set last contract {} data {} to {}", contract, key, topoheight);

        let contract_id = self.get_contract_id(contract)?;
        let contract_data_id = self.get_or_create_contract_data_id(key)?;
        let versioned_key = Self::get_versioned_contract_data_key(contract_id, contract_data_id, topoheight);

        self.insert_into_disk(Column::VersionedContractsData, &versioned_key, version)?;
        self.insert_into_disk(Column::ContractsData, &versioned_key[8..], &topoheight.to_be_bytes())
    }

    // Retrieve the last topoheight for a given contract data
    async fn get_last_topoheight_for_contract_data(&self, contract: &Hash, key: &ValueCell) -> Result<Option<TopoHeight>, BlockchainError> {
        trace!("get last topoheight for contract {} data {}", contract, key);
        let Some(contract_id) = self.get_optional_contract_id(contract)? else {
            return Ok(None)
        };
        let Some(contract_data_id) = self.get_optional_contract_data_id(key)? else {
            return Ok(None)
        };

        let key = Self::get_contract_data_key(contract_id, contract_data_id);
        self.load_optional_from_disk(Column::ContractsData, &key)
    }

    // Retrieve a contract data at a given topoheight
    async fn get_contract_data_at_exact_topoheight_for<'a>(&self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight) -> Result<VersionedContractData, BlockchainError> {
        trace!("get contract {} data {}  at exact topoheight {}", contract, key, topoheight);
        let contract_id = self.get_contract_id(contract)?;
        let contract_data_id = self.get_contract_data_id(key)?;
        let key = Self::get_versioned_contract_data_key(contract_id, contract_data_id, topoheight);
        self.load_from_disk(Column::VersionedContractsData, &key)
    }

    // Retrieve a contract data at maximum topoheight
    async fn get_contract_data_at_maximum_topoheight_for<'a>(&self, contract: &Hash, key: &ValueCell, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedContractData)>, BlockchainError> {
        trace!("get contract {} data {} at maximum topoheight {}", contract, key, maximum_topoheight);
        let Some(contract_id) = self.get_optional_contract_id(contract)? else {
            return Ok(None)
        };

        let Some(contract_data_id) = self.get_optional_contract_data_id(key)? else {
            return Ok(None)
        };

        if let Some(topo) = self.get_contract_data_topoheight_at_maximum_topoheight_for_internal(contract_id, contract_data_id, maximum_topoheight).await? {
            let versioned_key = Self::get_versioned_contract_data_key(contract_id, contract_data_id, topo);
            let version = self.load_from_disk(Column::VersionedContractsData, &versioned_key)?;
            return Ok(Some((topo, version)))
        }

        Ok(None)
    }

    // Retrieve the topoheight of a contract data at maximum topoheight
    async fn get_contract_data_topoheight_at_maximum_topoheight_for<'a>(&self, contract: &Hash, key: &ValueCell, maximum_topoheight: TopoHeight) -> Result<Option<TopoHeight>, BlockchainError> {
        trace!("get contract {} data {} topoheight at maximum topoheight {}", contract, key, maximum_topoheight);
        let Some(contract_id) = self.get_optional_contract_id(contract)? else {
            return Ok(None)
        };

        let Some(contract_data_id) = self.get_optional_contract_data_id(key)? else {
            return Ok(None)
        };

        self.get_contract_data_topoheight_at_maximum_topoheight_for_internal(contract_id, contract_data_id, maximum_topoheight).await
    }

    // Check if a contract data exists at a given topoheight
    // If the version is None, it returns false
    async fn has_contract_data_at_maximum_topoheight(&self, contract: &Hash, key: &ValueCell, maximum_topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("has contract {} data {} at maximum topoheight {}", contract, key, maximum_topoheight);
        let Some(contract_id) = self.get_optional_contract_id(contract)? else {
            return Ok(false)
        };

        let Some(contract_data_id) = self.get_optional_contract_data_id(key)? else {
            return Ok(false)
        };

        match self.get_contract_data_topoheight_at_maximum_topoheight_for_internal(contract_id, contract_data_id, maximum_topoheight).await? {
            Some(topoheight) => {
                let versioned_key = Self::get_versioned_contract_data_key(contract_id, contract_data_id, topoheight);
                let version = self.load_from_disk::<_, (Option<TopoHeight>, bool)>(Column::VersionedContractsData, &versioned_key)?;

                // Option encoded to 1 byte: None = 0, Some(_) = 1
                Ok(version.1)
            }
            None => Ok(false),
        }
    }

    // Check if we have a contract data version at a given topoheight
    // It only checks if the topoheight exists
    async fn has_contract_data_at_exact_topoheight(&self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("has contract {} data {} at exact topoheight {}", contract, key, topoheight);
        let contract_id = self.get_contract_id(contract)?;
        let contract_data_id = self.get_contract_data_id(key)?;
        let key = Self::get_versioned_contract_data_key(contract_id, contract_data_id, topoheight);
        self.load_from_disk(Column::VersionedContractsData, &key)
    }

    async fn get_contract_data_entries_at_maximum_topoheight<'a>(&'a self, contract: &'a Hash, topoheight: TopoHeight) -> Result<impl Stream<Item = Result<(ValueCell, ValueCell), BlockchainError>> + Send + 'a, BlockchainError> {
        trace!("get contract {} data entries at maximum topoheight {}", contract, topoheight);
        let contract_id = self.get_contract_id(contract)?;
        let iterator = self.iter_keys::<(u64, u64)>(Column::ContractsData, IteratorMode::WithPrefix(&contract_id.to_be_bytes(), Direction::Forward))?;
        Ok(stream::iter(iterator)
            .map(move |res| async move {
                let (_, data_id) = res?;
                match self.get_contract_data_topoheight_at_maximum_topoheight_for_internal(contract_id, data_id, topoheight).await? {
                    Some(topoheight) => {
                        let versioned_key = Self::get_versioned_contract_data_key(contract_id, data_id, topoheight);
                        let version = self.load_from_disk::<_, VersionedContractData>(Column::VersionedContractsData, &versioned_key)?
                            .take();

                        match version {
                            Some(data) => {
                                // Load the key from the data id
                                let key = self.load_from_disk(Column::ContractDataTableById, &data_id.to_be_bytes())?;
                                Ok(Some((key, data)))
                            },
                            None => Ok(None),
                        }
                    },
                    _ => Ok(None),
                }
            })
            .filter_map(|res| async move { res.await.transpose() })
        )
    }
}

impl RocksStorage {
    const NEXT_CONTRACT_DATA_ID: &[u8] = b"NCDID";

    async fn get_contract_data_topoheight_at_maximum_topoheight_for_internal(&self, contract_id: ContractId, contract_key_id: ContractDataId, maximum_topoheight: TopoHeight) -> Result<Option<TopoHeight>, BlockchainError> {
        trace!("get contract {} data {} at maximum topoheight {}", contract_id, contract_key_id, maximum_topoheight);

        let mut versioned_key = Self::get_versioned_contract_data_key(contract_id, contract_key_id, maximum_topoheight);
        let mut prev_topo: Option<TopoHeight> = self.load_optional_from_disk(Column::ContractsData, &versioned_key[8..])?;

        while let Some(topo) = prev_topo {
            versioned_key[0..8].copy_from_slice(&topo.to_be_bytes());
            if topo <= maximum_topoheight {
                return Ok(Some(topo))
            }

            prev_topo = self.load_optional_from_disk(Column::ContractsData, &versioned_key[8..])?;
        }

        Ok(None)
    }

    fn get_last_contract_data_id(&self) -> Result<ContractDataId, BlockchainError> {
        trace!("get current contract id");
        self.load_optional_from_disk(Column::Common, Self::NEXT_CONTRACT_DATA_ID)
            .map(|v| v.unwrap_or(0))
    }

    fn get_next_contract_data_id(&mut self) -> Result<ContractDataId, BlockchainError> {
        trace!("get next contract id");
        let id = self.get_last_contract_data_id()?;
        trace!("next contract id is {}", id);
        self.insert_into_disk(Column::Common, Self::NEXT_CONTRACT_DATA_ID, &(id + 1))?;

        Ok(id)
    }

    fn get_contract_data_id(&self, key: &ValueCell) -> Result<ContractDataId, BlockchainError> {
        self.load_from_disk(Column::ContractDataTable, &key.to_bytes())
    }

    fn get_optional_contract_data_id(&self, key: &ValueCell) -> Result<Option<ContractDataId>, BlockchainError> {
        self.load_optional_from_disk(Column::ContractDataTable, &key.to_bytes())
    }

    fn get_or_create_contract_data_id(&mut self, key: &ValueCell) -> Result<ContractDataId, BlockchainError> {
        trace!("get or create contract data id {}", key);
        let bytes = key.to_bytes();
        match self.get_optional_contract_data_id(key)? {
            Some(id) => Ok(id),
            None => {
                let id = self.get_next_contract_data_id()?;
                self.insert_into_disk(Column::ContractDataTable, &bytes, &id.to_be_bytes())?;
                self.insert_into_disk(Column::ContractDataTableById, &id.to_be_bytes(), &bytes.as_slice())?;

                Ok(id)
            }
        }
    }

    pub(super) fn get_contract_data_key(contract: ContractId, key: ContractDataId) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(&contract.to_be_bytes());
        buf[8..16].copy_from_slice(&key.to_be_bytes());
        buf
    }

    pub fn get_versioned_contract_data_key(contract: ContractDataId, key: ContractDataId, topoheight: TopoHeight) -> [u8; 24] {
        let mut buf = [0u8; 24];
        buf[0..8].copy_from_slice(&topoheight.to_be_bytes());
        buf[8..16].copy_from_slice(&contract.to_be_bytes());
        buf[16..24].copy_from_slice(&key.to_be_bytes());
        buf
    }
}