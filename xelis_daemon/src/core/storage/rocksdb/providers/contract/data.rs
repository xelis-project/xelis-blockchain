use async_trait::async_trait;
use futures::{stream, Stream, StreamExt};
use log::trace;
use rocksdb::Direction;
use xelis_vm::ValueCell;
use xelis_common::{
    block::TopoHeight,
    crypto::Hash,
    serializer::Serializer,
};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::{Column, ContractId, IteratorMode},
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
        let versioned_key = Self::get_versioned_contract_data_key(contract_id, key, topoheight);

        // We know the generated id is 16..24, so retrieve it to store the real key
        self.insert_into_disk(Column::ContractDataById, &versioned_key[16..24], key)?;

        self.insert_into_disk(Column::VersionedContractsData, &versioned_key, version)?;
        self.insert_into_disk(Column::ContractsData, &versioned_key[8..], &topoheight.to_be_bytes())
    }

    // Retrieve the last topoheight for a given contract data
    async fn get_last_topoheight_for_contract_data(&self, contract: &Hash, key: &ValueCell) -> Result<Option<TopoHeight>, BlockchainError> {
        trace!("get last topoheight for contract {} data {}", contract, key);
        let Some(contract_id) = self.get_optional_contract_id(contract)? else {
            return Ok(None)
        };
        let key = Self::get_contract_data_key(contract_id, key);
        self.load_optional_from_disk(Column::ContractsData, &key)
    }

    // Retrieve a contract data at a given topoheight
    async fn get_contract_data_at_exact_topoheight_for<'a>(&self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight) -> Result<VersionedContractData, BlockchainError> {
        trace!("get contract {} data {}  at exact topoheight {}", contract, key, topoheight);
        let contract_id = self.get_contract_id(contract)?;
        let key = Self::get_versioned_contract_data_key(contract_id, key, topoheight);
        self.load_from_disk(Column::VersionedContractsData, &key)
    }

    // Retrieve a contract data at maximum topoheight
    async fn get_contract_data_at_maximum_topoheight_for<'a>(&self, contract: &Hash, key: &ValueCell, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedContractData)>, BlockchainError> {
        trace!("get contract {} data {} at maximum topoheight {}", contract, key, maximum_topoheight);

        if let Some(topo) = self.get_contract_data_topoheight_at_maximum_topoheight_for(contract, key, maximum_topoheight).await? {
            let version = self.get_contract_data_at_exact_topoheight_for(contract, key, topo).await?;
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

        let mut versioned_key = Self::get_versioned_contract_data_key(contract_id, &key, maximum_topoheight);
        let mut prev_topo: Option<TopoHeight> = self.load_optional_from_disk(Column::ContractsData, &versioned_key[8..])?;

        while let Some(topo) = prev_topo {
            versioned_key[0..8].copy_from_slice(&topo.to_be_bytes());
            if topo <= maximum_topoheight {
                return Ok(Some(topo))
            }

            prev_topo = self.load_from_disk(Column::VersionedContractsData, &versioned_key).unwrap();
        }

        Ok(None)
    }

    // Check if a contract data exists at a given topoheight
    // If the version is None, it returns false
    async fn has_contract_data_at_maximum_topoheight(&self, contract: &Hash, key: &ValueCell, maximum_topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("has contract {} data {} at maximum topoheight {}", contract, key, maximum_topoheight);
        let Some(contract_id) = self.get_optional_contract_id(contract)? else {
            return Ok(false)
        };
        let mut versioned_key = Self::get_versioned_contract_data_key(contract_id, &key, maximum_topoheight);
        let mut prev_topo: Option<TopoHeight> = self.load_optional_from_disk(Column::ContractsData, &versioned_key[8..])?;

        while let Some(topo) = prev_topo {
            versioned_key[0..8].copy_from_slice(&topo.to_be_bytes());
            if topo <= maximum_topoheight {
                let has_data = self.load_from_disk::<_, (Option<TopoHeight>, bool)>(Column::VersionedContractsData, &versioned_key)?.1;
                return Ok(has_data)
            }

            prev_topo = self.load_from_disk(Column::VersionedContractsData, &versioned_key)?;
        }

        Ok(false)
    }

    // Check if we have a contract data version at a given topoheight
    // It only checks if the topoheight exists
    async fn has_contract_data_at_exact_topoheight(&self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("has contract {} data {} at exact topoheight {}", contract, key, topoheight);
        let contract_id = self.get_contract_id(contract)?;
        let key = Self::get_versioned_contract_data_key(contract_id, key, topoheight);
        self.load_from_disk(Column::VersionedContractsData, &key)
    }

    async fn get_contract_data_entries_at_maximum_topoheight<'a>(&'a self, contract: &'a Hash, topoheight: TopoHeight) -> Result<impl Stream<Item = Result<(ValueCell, ValueCell), BlockchainError>> + Send + 'a, BlockchainError> {
        let iterator = self.iter_keys::<u64>(Column::ContractsData, IteratorMode::WithPrefix(contract.as_bytes(), Direction::Forward))?;
        Ok(stream::iter(iterator)
            .map(move |res| async move {
                let id = res?;
                let key = self.load_from_disk(Column::ContractDataById, &id.to_be_bytes())?;
                // TODO: Optimize by a raw call instead of recalculating an id we already know
                let value = self.get_contract_data_at_maximum_topoheight_for(contract, &key, topoheight).await?;
                Ok(value.and_then(|(_, v)| v.take().map(|v| (key, v))))
            })
            .filter_map(|res| async move { res.await.transpose() })
        )
    }
}

impl RocksStorage {
    fn generate_data_id_for(contract: ContractId, key: &ValueCell) -> u64 {
        xxhash_rust::xxh3::xxh3_64_with_seed(&key.to_bytes(), contract)
    }

    pub(super) fn get_contract_data_key(contract: ContractId, key: &ValueCell) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(&contract.to_be_bytes());
        buf[8..16].copy_from_slice(&Self::generate_data_id_for(contract, key).to_be_bytes());
        buf
    }

    pub fn get_versioned_contract_data_key(contract: ContractId, key: &ValueCell, topoheight: TopoHeight) -> [u8; 24] {
        let mut buf = [0u8; 24];
        buf[0..8].copy_from_slice(&topoheight.to_be_bytes());
        buf[8..16].copy_from_slice(&contract.to_be_bytes());
        buf[16..24].copy_from_slice(&Self::generate_data_id_for(contract, key).to_be_bytes());
        buf
    }
}