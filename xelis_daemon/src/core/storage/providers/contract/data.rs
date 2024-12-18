use async_trait::async_trait;
use log::trace;
use xelis_common::{
    block::TopoHeight,
    crypto::{hash, Hash}, serializer::Serializer,
};
use xelis_vm::Constant;
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::{SledStorage, Versioned}
};

pub type VersionedContractData = Versioned<Constant>;

#[async_trait]
pub trait ContractDataProvider {
    // Set a contract data
    async fn set_last_contract_data_to<'a>(&mut self, hash: &Hash, topoheight: TopoHeight, contract: VersionedContractData) -> Result<(), BlockchainError>;

    // Set the last topoheight for a given contract data
    async fn set_last_topoheight_for_contract_data(&mut self, hash: &Hash, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // Retrieve the last topoheight for a given contract data
    async fn get_last_topoheight_for_contract_data(&self, hash: &Hash) -> Result<TopoHeight, BlockchainError>;

    // Retrieve a contract data at a given topoheight
    async fn get_contract_data_at_topoheight_for<'a>(&self, hash: &Hash, topoheight: TopoHeight) -> Result<VersionedContractData, BlockchainError>;

    // Retrieve a contract data at maximum topoheight
    async fn get_contract_data_at_maximum_topoheight_for<'a>(&self, hash: &Hash, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedContractData)>, BlockchainError>;

    // Store a contract data at a given topoheight
    async fn set_contract_data_at_topoheight<'a>(&mut self, hash: &Hash, topoheight: TopoHeight, contract: VersionedContractData) -> Result<(), BlockchainError>;

    // Check if a contract data exists at a given topoheight
    async fn has_contract_data_at_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError>;

    // Check if we have a contract data pointer
    async fn has_contract_data_pointer(&self, hash: &Hash) -> Result<bool, BlockchainError>;

    // Delete the last topoheight for a given contract data
    async fn delete_last_topoheight_for_contract_data(&mut self, hash: &Hash) -> Result<(), BlockchainError>;
}

#[async_trait]
impl ContractDataProvider for SledStorage {
    async fn set_last_contract_data_to<'a>(&mut self, hash: &Hash, topoheight: TopoHeight, contract: VersionedContractData) -> Result<(), BlockchainError> {
        trace!("set last contract data to topoheight {}", topoheight);
        self.set_contract_data_at_topoheight(hash, topoheight, contract).await?;
        self.set_last_topoheight_for_contract_data(hash, topoheight).await
    }

    async fn set_last_topoheight_for_contract_data(&mut self, hash: &Hash, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("set last topoheight for contract data to topoheight {}", topoheight);
        Self::insert_into_disk(self.snapshot.as_mut(), &self.contracts_data, hash.as_bytes(), &topoheight.to_be_bytes())?;
        Ok(())
    }

    async fn get_last_topoheight_for_contract_data(&self, hash: &Hash) -> Result<TopoHeight, BlockchainError> {
        trace!("get last topoheight for contract data");
        self.load_from_disk(&self.contracts_data, hash.as_bytes(), DiskContext::ContractDataTopoHeight)
    }

    async fn get_contract_data_at_topoheight_for<'a>(&self, hash: &Hash, topoheight: TopoHeight) -> Result<VersionedContractData, BlockchainError> {
        trace!("get contract data at topoheight {}", topoheight);
        self.load_from_disk(&self.versioned_contracts_data, &Self::get_versioned_contract_data_key(hash, topoheight), DiskContext::ContractData)
    }

    async fn get_contract_data_at_maximum_topoheight_for<'a>(&self, hash: &Hash, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedContractData)>, BlockchainError> {
        trace!("get contract data at maximum topoheight {}", maximum_topoheight);
        if !self.has_contract_data_pointer(hash).await? {
            trace!("Contract {} does not exist", hash);
            return Ok(None)
        }

        let topo = self.get_last_topoheight_for_contract_data(hash).await?;
        let mut previous_topo = Some(topo);
        while let Some(topoheight) = previous_topo {
            if topoheight <= maximum_topoheight {
                let version = self.get_contract_data_at_topoheight_for(hash, topoheight).await?;
                trace!("Contract data {} is at maximum topoheight", hash);
                return Ok(Some((topoheight, version)))
            }

            previous_topo = self.load_from_disk(
                &self.versioned_contracts,
                &Self::get_versioned_contract_data_key(hash, topoheight),
                DiskContext::ContractDataTopoHeight
            )?;
        }

        Ok(None)
    }

    async fn set_contract_data_at_topoheight<'a>(&mut self, hash: &Hash, topoheight: TopoHeight, contract: VersionedContractData) -> Result<(), BlockchainError> {
        trace!("set contract data at topoheight {}", topoheight);
        Self::insert_into_disk(self.snapshot.as_mut(), &self.versioned_contracts_data, Self::get_versioned_contract_data_key(hash, topoheight), contract.to_bytes())?;
        Ok(())
    }

    async fn has_contract_data_at_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("has contract data at topoheight {}", topoheight);
        self.contains_data(&self.versioned_contracts_data, &Self::get_versioned_contract_data_key(hash, topoheight))
    }

    async fn has_contract_data_pointer(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        trace!("has contract data pointer");
        self.contains_data(&self.contracts_data, hash.as_bytes())
    }

    async fn delete_last_topoheight_for_contract_data(&mut self, hash: &Hash) -> Result<(), BlockchainError> {
        trace!("delete last topoheight for contract data");
        Self::remove_from_disk(self.snapshot.as_mut(), &self.contracts_data, hash.as_bytes())?;
        Ok(())
    }
}

impl SledStorage {
    pub fn get_versioned_contract_data_key(hash: &Hash, topoheight: TopoHeight) -> [u8; 40] {
        let mut key = [0u8; 40];
        key[..8].copy_from_slice(&topoheight.to_be_bytes());
        key[8..].copy_from_slice(hash.as_bytes());
        key
    }

    pub fn get_contract_data_key(constant: &Constant, contract: &Hash) -> Hash {
        hash(&[constant.to_bytes(), contract.to_bytes()].concat())
    }
}