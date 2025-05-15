use async_trait::async_trait;
use log::trace;
use xelis_common::{
    block::TopoHeight,
    crypto::Hash
};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::{Column, Contract, ContractId, IteratorMode},
        ContractProvider,
        RocksStorage,
        VersionedContract
    }
};

#[async_trait]
impl ContractProvider for RocksStorage {
    // Deploy a contract
    async fn set_last_contract_to<'a>(&mut self, hash: &Hash, topoheight: TopoHeight, version: &VersionedContract<'a>) -> Result<(), BlockchainError> {
        let mut contract = self.get_or_create_contract_type(hash)?;
        contract.module_pointer = Some(topoheight);

        let versioned_key = Self::get_versioned_contract_key(contract.id, topoheight);

        self.insert_into_disk(Column::VersionedContracts, versioned_key, version)?;
        self.insert_into_disk(Column::Contracts, &versioned_key[8..], &contract)
    }

    // Retrieve the last topoheight for a given contract
    async fn get_last_topoheight_for_contract(&self, hash: &Hash) -> Result<Option<TopoHeight>, BlockchainError> {
        self.get_contract_type(hash)
            .map(|v| v.module_pointer)
    }

    // Retrieve a contract at a given topoheight
    async fn get_contract_at_topoheight_for<'a>(&self, hash: &Hash, topoheight: TopoHeight) -> Result<VersionedContract<'a>, BlockchainError> {
        let contract_id = self.get_contract_id(hash)?;
        let versioned_key = Self::get_versioned_contract_key(contract_id, topoheight);

        self.load_from_disk(Column::VersionedContracts, &versioned_key)
    }

    // Retrieve a contract at maximum topoheight
    async fn get_contract_at_maximum_topoheight_for<'a>(&self, hash: &Hash, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedContract<'a>)>, BlockchainError> {
        let contract = self.get_contract_type(hash)?;
        let Some(pointer) = contract.module_pointer else {
            return Ok(None)
        };

        let mut prev_topo = Some(pointer);
        while let Some(topo) = prev_topo {
            let versioned_key = Self::get_versioned_contract_key(contract.id, topo);
            if topo <= maximum_topoheight {
                let version = self.load_from_disk(Column::VersionedContracts, &versioned_key)?;
                return Ok(Some((topo, version)))
            }

            prev_topo = self.load_from_disk(Column::VersionedContracts, &versioned_key)?;
        }

        Ok(None)
    }

    // Retrieve all the contracts hashes
    async fn get_contracts<'a>(&'a self, minimum_topoheight: TopoHeight, maximum_topoheight: TopoHeight) -> Result<impl Iterator<Item = Result<Hash, BlockchainError>> + 'a, BlockchainError> {
        self.iter::<Hash, Contract>(Column::Contracts, IteratorMode::Start)
            .map(|iter| iter.map(move |res| {
                let (hash, contract) = res?;
                let Some(pointer) = contract.module_pointer else {
                    return Ok(None)
                };

                let mut prev_topo = Some(pointer);
                while let Some(topo) = prev_topo {
                    if topo < minimum_topoheight {
                        break;
                    }

                    if topo <= maximum_topoheight {
                        return Ok(Some(hash))
                    }

                    let versioned_key = Self::get_versioned_contract_key(contract.id, topo);
                    prev_topo = self.load_from_disk(Column::VersionedContracts, &versioned_key)?;
                }

                Ok(None)
            }).filter_map(Result::transpose))
    }

    // Delete the last topoheight for a given contract
    async fn delete_last_topoheight_for_contract(&mut self, hash: &Hash) -> Result<(), BlockchainError> {
        let mut contract = self.get_contract_type(hash)?;
        contract.module_pointer = None;

        self.insert_into_disk(Column::Contracts, hash, &contract)
    }

    // Check if a contract exists
    // and that it has a Module
    async fn has_contract(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        let contract = self.get_contract_type(hash)?;
        let Some(pointer) = contract.module_pointer else {
            return Ok(false)
        };

        let key = Self::get_versioned_contract_key(contract.id, pointer);
        // We can just read the Option as a bool because of how we store the data
        self.load_from_disk::<_, (Option<TopoHeight>, bool)>(Column::VersionedContracts, &key)
            .map(|v| v.1)
    }

    // Check if we have the contract
    async fn has_contract_pointer(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        self.get_contract_type(hash)
            .map(|v| v.module_pointer.is_some())
    }

    // Check if a contract exists at a given topoheight
    // If the version is None, it returns false
    async fn has_contract_module_at_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        let contract_id = self.get_contract_id(hash)?;
        let versioned_key = Self::get_versioned_contract_key(contract_id, topoheight);

        self.load_optional_from_disk::<_, (Option<TopoHeight>, bool)>(Column::VersionedContracts, &versioned_key)
            .map(|v| v.map_or(false, |v| v.1))
    }

    // Check if a contract version exists at a given topoheight
    async fn has_contract_at_exact_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        let contract_id = self.get_contract_id(hash)?;
        let versioned_key = Self::get_versioned_contract_key(contract_id, topoheight);

        self.contains_data(Column::VersionedContracts, &versioned_key)
    }

    // Check if a contract version exists at a maximum given topoheight
    async fn has_contract_at_maximum_topoheight(&self, hash: &Hash, maximum_topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        let contract = self.get_contract_type(hash)?;
        let Some(pointer) = contract.module_pointer else {
            return Ok(false)
        };

        let mut prev_topo = Some(pointer);
        while let Some(topo) = prev_topo {
            let versioned_key = Self::get_versioned_contract_key(contract.id, topo);
            if topo <= maximum_topoheight {
                let exists = self.load_from_disk::<_, (Option<TopoHeight>, bool)>(Column::VersionedContracts, &versioned_key)?.1;
                return Ok(exists)
            }

            prev_topo = self.load_from_disk(Column::VersionedContracts, &versioned_key)?;
        }

        Ok(false)
    }

    // Count the number of contracts
    async fn count_contracts(&self) -> Result<u64, BlockchainError> {
        self.get_last_contract_id()
    }
}

impl RocksStorage {
    const NEXT_CONTRACT_ID: &[u8] = b"NCID";

    fn get_last_contract_id(&self) -> Result<ContractId, BlockchainError> {
        trace!("get current contract id");
        self.load_optional_from_disk(Column::Common, Self::NEXT_CONTRACT_ID)
            .map(|v| v.unwrap_or(0))
    }

    fn get_next_contract_id(&mut self) -> Result<u64, BlockchainError> {
        trace!("get next contract id");
        let id = self.get_last_contract_id()?;
        trace!("next contract id is {}", id);
        self.insert_into_disk(Column::Common, Self::NEXT_CONTRACT_ID, &(id + 1))?;

        Ok(id)
    }

    pub(super) fn get_contract_id(&self, contract: &Hash) -> Result<ContractId, BlockchainError> {
        self.load_from_disk(Column::Contracts, contract)
    }

    pub fn get_contract_type(&self, contract: &Hash) -> Result<Contract, BlockchainError> {
        self.load_from_disk(Column::Contracts, contract)
    }


    pub(super) fn get_or_create_contract_type(&mut self, contract: &Hash) -> Result<Contract, BlockchainError> {
        match self.load_optional_from_disk::<_, Contract>(Column::Contracts, contract)? {
            Some(contract) => Ok(contract),
            None => {
                let id = self.get_next_contract_id()?;
                let contract = Contract {
                    id,
                    module_pointer: None
                };

                Ok(contract)
            }
        }
    }

    pub fn get_contract_from_id(&self, contract: ContractId) -> Result<Hash, BlockchainError> {
        self.load_from_disk(Column::ContractById, &contract.to_be_bytes())
    }

    pub fn get_versioned_contract_key(contract: ContractId, topoheight: TopoHeight) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(&topoheight.to_be_bytes());
        buf[8..16].copy_from_slice(&contract.to_be_bytes());

        buf
    }
}