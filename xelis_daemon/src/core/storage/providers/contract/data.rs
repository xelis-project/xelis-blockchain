use async_trait::async_trait;
use log::trace;
use xelis_common::{
    block::TopoHeight,
    crypto::{hash, Hash},
    serializer::Serializer,
    versioned_type::Versioned,
};
use xelis_vm::Constant;
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::SledStorage
};

// Versioned contract data
// Constant is optional because it can be deleted
pub type VersionedContractData = Versioned<Option<Constant>>;

#[async_trait]
pub trait ContractDataProvider {
    // Set a contract data
    async fn set_last_contract_data_to<'a>(&mut self, contract: &Hash, key: &Constant, topoheight: TopoHeight, contract: VersionedContractData) -> Result<(), BlockchainError>;

    // Set the last topoheight for a given contract data
    async fn set_last_topoheight_for_contract_data(&mut self, contract: &Hash, key: &Constant, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // Retrieve the last topoheight for a given contract data
    async fn get_last_topoheight_for_contract_data(&self, contract: &Hash, key: &Constant) -> Result<TopoHeight, BlockchainError>;

    // Retrieve a contract data at a given topoheight
    async fn get_contract_data_at_topoheight_for<'a>(&self, contract: &Hash, key: &Constant, topoheight: TopoHeight) -> Result<VersionedContractData, BlockchainError>;

    // Retrieve a contract data at maximum topoheight
    async fn get_contract_data_at_maximum_topoheight_for<'a>(&self, contract: &Hash, key: &Constant, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedContractData)>, BlockchainError>;

    // Retrieve the topoheight of a contract data at maximum topoheight
    async fn get_contract_data_topoheight_at_maximum_topoheight_for<'a>(&self, contract: &Hash, key: &Constant, maximum_topoheight: TopoHeight) -> Result<Option<TopoHeight>, BlockchainError>;

    // Store a contract data at a given topoheight
    async fn set_contract_data_at_topoheight<'a>(&mut self, contract: &Hash, key: &Constant, topoheight: TopoHeight, data: VersionedContractData) -> Result<(), BlockchainError>;

    // Check if a contract data exists at a given topoheight
    // If the version is None, it returns None
    async fn has_contract_data_at_topoheight(&self, contract: &Hash, key: &Constant, topoheight: TopoHeight) -> Result<bool, BlockchainError>;

    // Check if we have a contract data pointer
    async fn has_contract_data_pointer(&self, contract: &Hash, key: &Constant) -> Result<bool, BlockchainError>;

    // Delete the last topoheight for a given contract data
    async fn delete_last_topoheight_for_contract_data(&mut self, contract: &Hash, key: &Constant) -> Result<(), BlockchainError>;
}

#[async_trait]
impl ContractDataProvider for SledStorage {
    async fn set_last_contract_data_to<'a>(&mut self, contract: &Hash, key: &Constant, topoheight: TopoHeight, data: VersionedContractData) -> Result<(), BlockchainError> {
        trace!("set last contract data to topoheight {}", topoheight);
        self.set_contract_data_at_topoheight(contract, key, topoheight, data).await?;
        self.set_last_topoheight_for_contract_data(contract, key, topoheight).await
    }

    async fn set_last_topoheight_for_contract_data(&mut self, contract: &Hash, key: &Constant, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("set last topoheight for contract data to topoheight {}", topoheight);
        let hash = Self::get_contract_data_key(key, contract);
        Self::insert_into_disk(self.snapshot.as_mut(), &self.contracts_data, hash.as_bytes(), &topoheight.to_be_bytes())?;
        Ok(())
    }

    async fn get_last_topoheight_for_contract_data(&self, contract: &Hash, key: &Constant) -> Result<TopoHeight, BlockchainError> {
        trace!("get last topoheight for contract data");
        let hash = Self::get_contract_data_key(key, contract);
        self.load_from_disk(&self.contracts_data, hash.as_bytes(), DiskContext::ContractDataTopoHeight)
    }

    async fn get_contract_data_at_topoheight_for<'a>(&self, contract: &Hash, key: &Constant, topoheight: TopoHeight) -> Result<VersionedContractData, BlockchainError> {
        trace!("get contract data at topoheight {}", topoheight);
        self.load_from_disk(&self.versioned_contracts_data, &Self::get_versioned_contract_data_key(contract, key, topoheight), DiskContext::ContractData)
    }

    async fn get_contract_data_at_maximum_topoheight_for<'a>(&self, contract: &Hash, key: &Constant, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedContractData)>, BlockchainError> {
        trace!("get contract data at maximum topoheight {}", maximum_topoheight);
        match self.get_contract_data_topoheight_at_maximum_topoheight_for(contract, key, maximum_topoheight).await? {
            Some(topoheight) => {
                let contract = self.get_contract_data_at_topoheight_for(&contract, key, topoheight).await?;
                Ok(Some((topoheight, contract)))
            },
            None => Ok(None)
        }
    }

    async fn get_contract_data_topoheight_at_maximum_topoheight_for<'a>(&self, contract: &Hash, key: &Constant, maximum_topoheight: TopoHeight) -> Result<Option<TopoHeight>, BlockchainError> {
        trace!("get contract data topoheight at maximum topoheight {}", maximum_topoheight);
        if !self.has_contract_data_pointer(contract, key).await? {
            trace!("Contract {} does not exist", contract);
            return Ok(None)
        }

        let topo = self.get_last_topoheight_for_contract_data(contract, key).await?;
        let mut previous_topo = Some(topo);
        while let Some(topoheight) = previous_topo {
            if topoheight <= maximum_topoheight {
                trace!("Contract data topoheight {} is at maximum topoheight", topoheight);
                return Ok(Some(topoheight))
            }

            previous_topo = self.load_from_disk(
                &self.versioned_contracts,
                &Self::get_versioned_contract_data_key(&contract, key, topoheight),
                DiskContext::ContractDataTopoHeight
            )?;
        }

        Ok(None)
    }

    async fn set_contract_data_at_topoheight<'a>(&mut self, contract: &Hash, key: &Constant, topoheight: TopoHeight, data: VersionedContractData) -> Result<(), BlockchainError> {
        trace!("set contract data at topoheight {}", topoheight);
        Self::insert_into_disk(self.snapshot.as_mut(), &self.versioned_contracts_data, Self::get_versioned_contract_data_key(contract, key, topoheight), data.to_bytes())?;
        Ok(())
    }

    async fn has_contract_data_at_topoheight(&self, contract: &Hash, key: &Constant, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("has contract data at topoheight {}", topoheight);
        self.get_contract_data_at_topoheight_for(contract, key, topoheight).await.map(|res| res.take().is_some())
    }

    async fn has_contract_data_pointer(&self, contract: &Hash, key: &Constant) -> Result<bool, BlockchainError> {
        trace!("has contract data pointer");
        let hash = Self::get_contract_data_key(key, contract);
        self.contains_data(&self.contracts_data, hash.as_bytes())
    }

    async fn delete_last_topoheight_for_contract_data(&mut self, contract: &Hash, key: &Constant) -> Result<(), BlockchainError> {
        trace!("delete last topoheight for contract data");
        let hash = Self::get_contract_data_key(key, contract);
        Self::remove_from_disk(self.snapshot.as_mut(), &self.contracts_data, hash.as_bytes())?;
        Ok(())
    }
}

impl SledStorage {
    pub fn get_versioned_contract_data_key(contract: &Hash, key: &Constant, topoheight: TopoHeight) -> [u8; 40] {
        let mut buffer = [0u8; 40];
        buffer[..8].copy_from_slice(&topoheight.to_be_bytes());
        buffer[8..].copy_from_slice(Self::get_contract_data_key(key, contract).as_bytes());
        buffer
    }

    pub fn get_contract_data_key(constant: &Constant, contract: &Hash) -> Hash {
        hash(&[constant.to_bytes(), contract.to_bytes()].concat())
    }
}