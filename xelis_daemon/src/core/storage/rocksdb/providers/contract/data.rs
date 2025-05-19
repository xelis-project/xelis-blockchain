use async_trait::async_trait;
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
        rocksdb::{Column, ContractId},
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
        self.insert_into_disk(Column::VersionedContractsData, &versioned_key, version)?;
        self.insert_into_disk(Column::ContractsData, &versioned_key[8..], &topoheight.to_be_bytes())
    }

    // Retrieve the last topoheight for a given contract data
    async fn get_last_topoheight_for_contract_data(&self, contract: &Hash, key: &ValueCell) -> Result<Option<TopoHeight>, BlockchainError> {
        trace!("get last topoheight for contract {} data {}", contract, key);
        let contract_id = self.get_contract_id(contract)?;
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
        let contract_id = self.get_contract_id(contract)?;
        let mut versioned_key = Self::get_versioned_contract_data_key(contract_id, &key, maximum_topoheight);
        let mut prev_topo: Option<TopoHeight> = self.load_optional_from_disk(Column::ContractsData, &versioned_key[8..])?;

        while let Some(topo) = prev_topo {
            versioned_key[0..8].copy_from_slice(&topo.to_be_bytes());
            if topo <= maximum_topoheight {
                return Ok(Some(topo))
            }

            prev_topo = self.load_from_disk(Column::VersionedContractsData, &versioned_key)?;
        }

        Ok(None)
    }

    // Check if a contract data exists at a given topoheight
    // If the version is None, it returns false
    async fn has_contract_data_at_maximum_topoheight(&self, contract: &Hash, key: &ValueCell, maximum_topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("has contract {} data {} at maximum topoheight {}", contract, key, maximum_topoheight);
        let contract_id = self.get_contract_id(contract)?;
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