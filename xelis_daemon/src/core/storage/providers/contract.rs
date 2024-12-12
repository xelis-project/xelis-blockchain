use std::borrow::Cow;

use async_trait::async_trait;
use indexmap::IndexSet;
use xelis_common::{block::TopoHeight, crypto::Hash, serializer::Serializer};
use xelis_vm::{Environment, Module};
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::{SledStorage, Versioned, CONTRACTS_COUNT}
};
use log::trace;

// A versioned contract is a contract that can be updated or deleted
pub type VersionedContract<'a> = Versioned<Option<Cow<'a, Module>>>;

#[async_trait]
pub trait ContractProvider {
    // Deploy a contract
    async fn set_last_contract_to<'a>(&mut self, hash: &Hash, topoheight: TopoHeight, contract: VersionedContract<'a>) -> Result<(), BlockchainError>;

    // Set the last topoheight for a given contract
    async fn set_last_topoheight_for_contract(&mut self, hash: &Hash, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // Retrieve the last topoheight for a given contract
    async fn get_last_topoheight_for_contract(&self, hash: &Hash) -> Result<TopoHeight, BlockchainError>;

    // Retrieve a contract at a given topoheight
    async fn get_contract_at_topoheight_for<'a>(&self, hash: &Hash, topoheight: TopoHeight) -> Result<VersionedContract<'a>, BlockchainError>;

    // Retrieve a contract at maximum topoheight
    async fn get_contract_at_maximum_topoheight_for<'a>(&self, hash: &Hash, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedContract<'a>)>, BlockchainError>;

    // Retrieve all the contracts hashes
    async fn get_contracts(&self, maximum: usize, skip: usize, minimum_topoheight: TopoHeight, maximum_topoheight: TopoHeight) -> Result<IndexSet<Hash>, BlockchainError>;

    // Retrieve the size of a contract at a given topoheight without loading the contract
    async fn get_contract_size_at_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<usize, BlockchainError>;

    // Store a contract at a given topoheight
    async fn set_contract_at_topoheight<'a>(&mut self, hash: &Hash, topoheight: TopoHeight, contract: VersionedContract<'a>) -> Result<(), BlockchainError>;

    // Delete the last topoheight for a given contract
    async fn delete_last_topoheight_for_contract(&mut self, hash: &Hash) -> Result<(), BlockchainError>;

    // Check if a contract exists
    // and that it has a Module
    async fn has_contract(&self, hash: &Hash) -> Result<bool, BlockchainError>;

    // Check if we have the contract
    async fn has_contract_pointer(&self, hash: &Hash) -> Result<bool, BlockchainError>;

    // Check if a contract exists at a given topoheight
    async fn has_contract_at_exact_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError>;

    // Count the number of contracts
    async fn count_contracts(&self) -> Result<u64, BlockchainError>;

    // Get the environment to use for contract execution
    async fn get_contract_environment(&self) -> Result<&Environment, BlockchainError>;
}

#[async_trait]
impl ContractProvider for SledStorage {
    async fn set_last_contract_to<'a>(&mut self, hash: &Hash, topoheight: TopoHeight, contract: VersionedContract<'a>) -> Result<(), BlockchainError> {
        trace!("Setting contract {} at topoheight {}", hash, topoheight);
        self.set_contract_at_topoheight(hash, topoheight, contract).await?;
        self.set_last_topoheight_for_contract(hash, topoheight).await?;
        Ok(())
    }

    async fn set_last_topoheight_for_contract(&mut self, hash: &Hash, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("Setting last topoheight for contract {} to {}", hash, topoheight);
        let prev = Self::insert_into_disk(self.snapshot.as_mut(), &self.contracts, hash.as_bytes(), &topoheight.to_be_bytes())?;
        if prev.is_none() {
            self.store_contracts_count(self.count_contracts().await? + 1)?;
        }

        Ok(())
    }

    async fn get_last_topoheight_for_contract(&self, hash: &Hash) -> Result<TopoHeight, BlockchainError> {
        trace!("Getting last topoheight for contract {}", hash);
        self.load_from_disk(&self.contracts, hash.as_bytes(), DiskContext::ContractTopoHeight)   
    }

    async fn get_contract_at_topoheight_for<'a>(&self, hash: &Hash, topoheight: TopoHeight) -> Result<VersionedContract<'a>, BlockchainError> {
        trace!("Getting contract {} at topoheight {}", hash, topoheight);
        let key = Self::get_versioned_contract_key(hash, topoheight);
        self.load_from_disk(&self.versioned_contracts, &key, DiskContext::ContractTopoHeight)
    }

    async fn get_contract_size_at_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<usize, BlockchainError> {
        trace!("Getting contract size at topoheight {}", topoheight);
        let key = Self::get_versioned_contract_key(hash, topoheight);
        self.get_size_from_disk(&self.versioned_contracts, &key)
    }

    async fn get_contract_at_maximum_topoheight_for<'a>(&self, hash: &Hash, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedContract<'a>)>, BlockchainError> {
        trace!("Getting contract {} at maximum topoheight {}", hash, maximum_topoheight);
        if !self.has_contract_pointer(hash).await? {
            trace!("Contract {} does not exist", hash);
            return Ok(None)
        }

        let topoheight = self.get_last_topoheight_for_contract(hash).await?;

        if topoheight <= maximum_topoheight {
            let version = self.get_contract_at_topoheight_for(hash, topoheight).await?;
            trace!("Contract {} is at maximum topoheight", hash);
            return Ok(Some((topoheight, version)))
        }

        // We need to go through all the previous versions to get the first one that matches the maximum topoheight
        let mut previous_topo = self.load_from_disk(
            &self.versioned_contracts,
            &Self::get_versioned_contract_key(hash, topoheight),
            DiskContext::ContractTopoHeight
        )?;

        while let Some(topoheight) = previous_topo {
            if topoheight <= maximum_topoheight {
                let version = self.get_contract_at_topoheight_for(hash, topoheight).await?;
                trace!("Contract {} is at maximum topoheight", hash);
                return Ok(Some((topoheight, version)))
            }

            previous_topo = self.load_from_disk(
                &self.versioned_contracts,
                &Self::get_versioned_contract_key(hash, topoheight),
                DiskContext::ContractTopoHeight
            )?;
        }

        Ok(None)
    }

    async fn get_contracts(&self, maximum: usize, skip: usize, minimum_topoheight: TopoHeight, maximum_topoheight: TopoHeight) -> Result<IndexSet<Hash>, BlockchainError> {
        trace!("Getting contracts, maximum: {}, skip: {}, minimum_topoheight: {}, maximum_topoheight: {}", maximum, skip, minimum_topoheight, maximum_topoheight);
        let mut contracts = IndexSet::new();
        let mut skip_count = 0;

        // Unlike the keys, we don't prefix them with a topoheight at which they got registered
        // Because we allow contracts code to be updated, we need to get the latest version of the contract
        // We can't do a fast path with the skip checking, we need to process them all
        for el in self.contracts.iter() {
            let (key, value) = el?;
            let topoheight = TopoHeight::from_bytes(&value)?;
            let hash = Hash::from_bytes(&key)?;

            let mut found = false;
            let mut prev_topoheight = Some(topoheight);
            while let Some(topoheight) = prev_topoheight.take() {
                if topoheight < minimum_topoheight {
                    break;
                }

                if topoheight < maximum_topoheight {
                    found = true;
                    break;
                }

                let key = Self::get_versioned_contract_key(&hash, topoheight);
                prev_topoheight = self.load_from_disk(&self.versioned_contracts, &key, DiskContext::ContractTopoHeight)?;
            }

            if !found {
                continue;
            }

            if skip_count < skip {
                skip_count += 1;
                continue;
            }

            contracts.insert(hash);
            if contracts.len() >= maximum {
                break;
            }
        }

        Ok(contracts)
    }

    async fn set_contract_at_topoheight<'a>(&mut self, hash: &Hash, topoheight: TopoHeight, contract: VersionedContract<'a>) -> Result<(), BlockchainError> {
        trace!("Setting contract {} at topoheight {}", hash, topoheight);
        let key = Self::get_versioned_contract_key(hash, topoheight);
        Self::insert_into_disk(self.snapshot.as_mut(), &self.versioned_contracts, &key, contract.to_bytes())?;
        Ok(())
    }

    async fn delete_last_topoheight_for_contract(&mut self, hash: &Hash) -> Result<(), BlockchainError> {
        trace!("Deleting last topoheight for contract {}", hash);
        let prev = Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.contracts, hash.as_bytes())?;
        if prev {
            self.store_contracts_count(self.count_contracts().await? - 1)?;
        }
        Ok(())
    }

    async fn has_contract_pointer(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        trace!("Checking if contract {} exists", hash);
        self.contains_data(&self.contracts, hash.as_bytes())
    }

    async fn has_contract(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        trace!("Checking if contract {} exists", hash);
        let topoheight = self.get_last_topoheight_for_contract(hash).await?;
        self.has_contract_at_exact_topoheight(hash, topoheight).await
    }

    async fn has_contract_at_exact_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("Checking if contract {} exists at topoheight {}", hash, topoheight);
        let contract = self.get_contract_at_topoheight_for(hash, topoheight).await?;
        Ok(contract.get().is_some())
    }

    async fn count_contracts(&self) -> Result<u64, BlockchainError> {
        trace!("Counting contracts");
        let count = if let Some(snapshot) = self.snapshot.as_ref() {
            snapshot.contracts_count
        } else {
            self.contracts_count
        };

        Ok(count)
    }

    async fn get_contract_environment(&self) -> Result<&Environment, BlockchainError> {
        trace!("Getting contract environment");
        Ok(&self.environment)
    }
}

impl SledStorage {
    // Update the contracts count and store it on disk
    pub fn store_contracts_count(&mut self, count: u64) -> Result<(), BlockchainError> {
        trace!("Storing contracts count: {}", count);
        if let Some(snapshot) = self.snapshot.as_mut() {
            snapshot.contracts_count = count;
        } else {
            self.contracts_count = count;
        }
        Self::insert_into_disk(self.snapshot.as_mut(), &self.extra, CONTRACTS_COUNT, &count.to_be_bytes())?;
        Ok(())
    }

    fn get_versioned_contract_key(hash: &Hash, topoheight: TopoHeight) -> [u8; 40] {
        let mut key = [0; 40];
        key[..8].copy_from_slice(&topoheight.to_be_bytes());
        key[8..].copy_from_slice(hash.as_bytes());
        key
    }
}