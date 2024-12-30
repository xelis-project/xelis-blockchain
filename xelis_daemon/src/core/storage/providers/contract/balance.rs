use async_trait::async_trait;
use xelis_common::{block::TopoHeight, crypto::{Hash, HASH_SIZE}, serializer::Serializer, versioned_type::Versioned};

use crate::core::{error::{BlockchainError, DiskContext}, storage::SledStorage};

pub type VersionedContractBalance = Versioned<u64>;

#[async_trait]
pub trait ContractBalanceProvider {
    // Check if a balance exists for asset and contract
    async fn has_contract_balance_for(&self, contract: &Hash, asset: &Hash) -> Result<bool, BlockchainError>;

    // Check if a balance exists for asset and contract at specific topoheight
    async fn has_contract_balance_at_exact_topoheight(&self, contract: &Hash, asset: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError>;

    // Get the balance at a specific topoheight for asset and contract
    async fn get_contract_balance_at_exact_topoheight(&self, contract: &Hash, asset: &Hash, topoheight: TopoHeight) -> Result<VersionedContractBalance, BlockchainError>;

    // Get the balance under or equal topoheight requested for asset and contract
    async fn get_contract_balance_at_maximum_topoheight(&self, contract: &Hash, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedContractBalance)>, BlockchainError>;

    // Get the last topoheight that the contract has a balance
    async fn get_last_topoheight_for_contract_balance(&self, contract: &Hash, asset: &Hash) -> Result<Option<TopoHeight>, BlockchainError>;

    async fn get_last_contract_balance(&self, contract: &Hash, asset: &Hash) -> Result<(TopoHeight, VersionedContractBalance), BlockchainError>;

    // Set the last topoheight that the contract has a balance
    async fn set_last_topoheight_for_contract_balance(&mut self, contract: &Hash, asset: &Hash, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // Set the last balance for asset and contract at specific topoheight
    async fn set_last_contract_balance_to(&mut self, contract: &Hash, asset: &Hash, topoheight: TopoHeight, balance: VersionedContractBalance) -> Result<(), BlockchainError>;
}

#[async_trait]
impl ContractBalanceProvider for SledStorage {
    async fn has_contract_balance_for(&self, contract: &Hash, asset: &Hash) -> Result<bool, BlockchainError> {
        let key = Self::get_contract_balance_key(contract, asset);
        self.contains_data(&self.contracts_balances, &key)
    }

    async fn has_contract_balance_at_exact_topoheight(&self, contract: &Hash, asset: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        let key = Self::get_versioned_key(Self::get_contract_balance_key(contract, asset), topoheight);
        self.contains_data(&self.versioned_contracts_balances, &key)
    }

    async fn get_contract_balance_at_exact_topoheight(&self, contract: &Hash, asset: &Hash, topoheight: TopoHeight) -> Result<VersionedContractBalance, BlockchainError> {
        let key = Self::get_versioned_key(Self::get_contract_balance_key(contract, asset), topoheight);
        self.load_from_disk(&self.versioned_contracts_balances, &key, DiskContext::ContractBalance)
    }

    async fn get_contract_balance_at_maximum_topoheight(&self, contract: &Hash, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedContractBalance)>, BlockchainError> {
        if let Some(topo) = self.get_last_topoheight_for_contract_balance(contract, asset).await? {
            let k = Self::get_contract_balance_key(contract, asset);
            let mut prev_topo = Some(topo);
            while let Some(topo) = prev_topo {
                let key = Self::get_versioned_key(&k, topo);
                if topo <= topoheight {
                    let balance: VersionedContractBalance = self.load_from_disk(&self.versioned_contracts_balances, &key, DiskContext::ContractBalance)?;
                    return Ok(Some((topo, balance)));
                }

                prev_topo = self.load_from_disk(&self.versioned_contracts_balances, &key, DiskContext::ContractBalance)?;
            }
        }

        Ok(None)
    }

    async fn get_last_topoheight_for_contract_balance(&self, contract: &Hash, asset: &Hash) -> Result<Option<TopoHeight>, BlockchainError> {
        self.load_optional_from_disk(&self.contracts_balances, &Self::get_contract_balance_key(contract, asset))
    }

    async fn get_last_contract_balance(&self, contract: &Hash, asset: &Hash) -> Result<(TopoHeight, VersionedContractBalance), BlockchainError> {
        let Some(topoheight) = self.get_last_topoheight_for_contract_balance(contract, asset).await? else {
            return Err(BlockchainError::NoContractBalance);
        };

        let key = Self::get_versioned_key(Self::get_contract_balance_key(contract, asset), topoheight);
        Ok((topoheight, self.load_from_disk(&self.versioned_contracts_balances, &key, DiskContext::ContractBalance)?))
    }

    async fn set_last_topoheight_for_contract_balance(&mut self, contract: &Hash, asset: &Hash, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        Self::insert_into_disk(self.snapshot.as_mut(), &self.contracts_balances, &Self::get_contract_balance_key(contract, asset), &topoheight.to_be_bytes())?;
        Ok(())
    }

    async fn set_last_contract_balance_to(&mut self, contract: &Hash, asset: &Hash, topoheight: TopoHeight, balance: VersionedContractBalance) -> Result<(), BlockchainError> {
        let key = Self::get_versioned_key(Self::get_contract_balance_key(contract, asset), topoheight);
        Self::insert_into_disk(self.snapshot.as_mut(), &self.versioned_contracts_balances, &key, balance.to_bytes())?;

        self.set_last_topoheight_for_contract_balance(contract, asset, topoheight).await
    }
}

impl SledStorage {
    pub fn get_contract_balance_key(contract: &Hash, asset: &Hash) -> Vec<u8> {
        let mut key = Vec::with_capacity(HASH_SIZE * 2);
        key.extend_from_slice(contract.as_ref());
        key.extend_from_slice(asset.as_ref());
        key
    }
}