mod data;
mod contract_logs;
mod provider;
mod balance;
mod scheduled_execution;

use async_trait::async_trait;
use xelis_common::{
    block::TopoHeight,
    crypto::Hash,
    serializer::Serializer,
};
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::{
        ContractProvider,
        SledStorage,
        VersionedContract,
        sled::CONTRACTS_COUNT
    }
};
use log::trace;

#[async_trait]
impl ContractProvider for SledStorage {
    async fn set_last_contract_to<'a>(&mut self, hash: &Hash, topoheight: TopoHeight, contract: &VersionedContract<'a>) -> Result<(), BlockchainError> {
        trace!("Setting contract {} at topoheight {}", hash, topoheight);
        let key = self.get_versioned_contract_key(hash, topoheight);
        Self::insert_into_disk(self.snapshot.as_mut(), &self.versioned_contracts, &key, contract.to_bytes())?;

        if Self::insert_into_disk(self.snapshot.as_mut(), &self.contracts, hash.as_bytes(), &topoheight.to_be_bytes())? {
            self.store_contracts_count(self.count_contracts().await? + 1)?;
        }

        Ok(())
    }

    async fn get_last_topoheight_for_contract(&self, hash: &Hash) -> Result<Option<TopoHeight>, BlockchainError> {
        trace!("Getting last topoheight for contract {}", hash);
        self.load_optional_from_disk(&self.contracts, hash.as_bytes())   
    }

    async fn get_contract_at_topoheight_for<'a>(&self, hash: &Hash, topoheight: TopoHeight) -> Result<VersionedContract<'a>, BlockchainError> {
        trace!("Getting contract {} at topoheight {}", hash, topoheight);
        let key = self.get_versioned_contract_key(hash, topoheight);
        self.load_from_disk(&self.versioned_contracts, &key, DiskContext::ContractTopoHeight)
    }

    async fn get_contract_at_maximum_topoheight_for<'a>(&self, hash: &Hash, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedContract<'a>)>, BlockchainError> {
        trace!("Getting contract {} at maximum topoheight {}", hash, maximum_topoheight);
        let Some(pointer) = self.get_last_topoheight_for_contract(hash).await? else {
            return Ok(None)
        };

        let topo = if self.has_contract_at_exact_topoheight(hash, maximum_topoheight).await? {
            maximum_topoheight
        } else {
            pointer
        };

        let mut previous_topo = Some(topo);
        while let Some(topoheight) = previous_topo {
            if topoheight <= maximum_topoheight {
                let version = self.get_contract_at_topoheight_for(hash, topoheight).await?;
                trace!("Contract {} is at maximum topoheight", hash);
                return Ok(Some((topoheight, version)))
            }

            previous_topo = self.load_from_disk(
                &self.versioned_contracts,
                &self.get_versioned_contract_key(hash, topoheight),
                DiskContext::ContractTopoHeight
            )?;
        }

        Ok(None)
    }

    async fn has_contract_at_maximum_topoheight(&self, hash: &Hash, maximum_topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("has contract {} at maximum topoheight {}", hash, maximum_topoheight);
        let Some(pointer) = self.get_last_topoheight_for_contract(hash).await? else {
            return Ok(false)
        };

        let mut previous_topo = Some(pointer);
        while let Some(topoheight) = previous_topo {
            if topoheight <= maximum_topoheight {
                let exists = self.load_from_disk::<(Option<TopoHeight>, bool)>(
                    &self.versioned_contracts,
                    &self.get_versioned_contract_key(hash, topoheight),
                    DiskContext::ContractTopoHeight
                )?.1;

                return Ok(exists)
            }

            previous_topo = self.load_from_disk(
                &self.versioned_contracts,
                &self.get_versioned_contract_key(hash, topoheight),
                DiskContext::ContractTopoHeight
            )?;
        }

        Ok(false)
    }

    async fn get_contracts<'a>(&'a self, minimum_topoheight: TopoHeight, maximum_topoheight: TopoHeight) -> Result<impl Iterator<Item = Result<Hash, BlockchainError>> + 'a, BlockchainError> {
        trace!("Getting contracts, minimum_topoheight: {}, maximum_topoheight: {}", minimum_topoheight, maximum_topoheight);

        Ok(Self::iter::<Hash, TopoHeight>(self.snapshot.as_ref(), &self.contracts)
            .map(move |el| {
                let (hash, topoheight) = el?;

                // We must check that we don't have a version
                // in our range

                let mut prev_topo = Some(topoheight);
                while let Some(topo) = prev_topo {
                    if topoheight < minimum_topoheight {
                        break;
                    }

                    if topo <= maximum_topoheight {
                        return Ok(Some(hash))
                    }

                    let versioned_key = Self::get_versioned_contract_key(&self, &hash, topo);
                    prev_topo = self.load_from_disk(&self.versioned_contracts, &versioned_key, DiskContext::ContractAtTopoHeight(topo))?;
                }

                Ok(None)
            })
            .filter_map(Result::transpose)
        )
    }

    async fn delete_last_topoheight_for_contract(&mut self, hash: &Hash) -> Result<(), BlockchainError> {
        trace!("Deleting last topoheight for contract {}", hash);
        if Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.contracts, hash.as_bytes())? {
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
        let Some(pointer) = self.get_last_topoheight_for_contract(hash).await? else {
            return Ok(false)
        };
        
        self.has_contract_module_at_topoheight(hash, pointer).await
    }

    async fn has_contract_module_at_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("Checking if contract module {} exists at topoheight {}", hash, topoheight);
        let contract = self.get_contract_at_topoheight_for(hash, topoheight).await?;
        Ok(contract.get().is_some())
    }

    async fn has_contract_at_exact_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("Checking if contract {} exists at exact topoheight {}", hash, topoheight);
        let key = self.get_versioned_contract_key(hash, topoheight);
        self.contains_data(&self.versioned_contracts, &key)
    }

    async fn count_contracts(&self) -> Result<u64, BlockchainError> {
        trace!("Counting contracts");

        Ok(self.cache().contracts_count)
    }
}

impl SledStorage {
    // Update the contracts count and store it on disk
    pub fn store_contracts_count(&mut self, count: u64) -> Result<(), BlockchainError> {
        trace!("Storing contracts count: {}", count);
        self.cache_mut().contracts_count = count;
        Self::insert_into_disk(self.snapshot.as_mut(), &self.extra, CONTRACTS_COUNT, &count.to_be_bytes())?;
        Ok(())
    }

    pub(super) fn get_versioned_contract_key(&self, hash: &Hash, topoheight: TopoHeight) -> [u8; 40] {
        let mut key = [0; 40];
        key[..8].copy_from_slice(&topoheight.to_be_bytes());
        key[8..].copy_from_slice(hash.as_bytes());
        key
    }
}