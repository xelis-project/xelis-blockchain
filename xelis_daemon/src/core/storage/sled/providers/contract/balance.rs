use async_trait::async_trait;
use log::trace;
use xelis_common::{
    block::TopoHeight,
    crypto::{Hash, HASH_SIZE},
    serializer::Serializer
};
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::{
        ContractBalanceProvider,
        VersionedContractBalance,
        SledStorage
    }
};

#[async_trait]
impl ContractBalanceProvider for SledStorage {
    async fn has_contract_balance_for(&self, contract: &Hash, asset: &Hash) -> Result<bool, BlockchainError> {
        trace!("has contract {} balance {}", contract, asset);
        let key = Self::get_contract_balance_key(contract, asset);
        self.contains_data(&self.contracts_balances, &key)
    }

    async fn has_contract_balance_at_exact_topoheight(&self, contract: &Hash, asset: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("has contract {} balance {} at exact topoheight {}", contract, asset, topoheight);
        let key = Self::get_versioned_key(Self::get_contract_balance_key(contract, asset), topoheight);
        self.contains_data(&self.versioned_contracts_balances, &key)
    }

    async fn get_contract_balance_at_exact_topoheight(&self, contract: &Hash, asset: &Hash, topoheight: TopoHeight) -> Result<VersionedContractBalance, BlockchainError> {
        trace!("get contract {} balance {} at exact topoheight {}", contract, asset, topoheight);
        let key = Self::get_versioned_key(Self::get_contract_balance_key(contract, asset), topoheight);
        self.load_from_disk(&self.versioned_contracts_balances, &key, DiskContext::ContractBalance)
    }

    async fn get_contract_balance_at_maximum_topoheight(&self, contract: &Hash, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedContractBalance)>, BlockchainError> {
        trace!("get contract {} balance {} at maximum topoheight {}", contract, asset, topoheight);
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

    async fn get_contract_assets_for<'a>(&'a self, contract: &'a Hash) -> Result<impl Iterator<Item = Result<Hash, BlockchainError>> + 'a, BlockchainError> {
        trace!("get contract assets for {}", contract);
        Ok(Self::scan_prefix(self.snapshot.as_ref(), &self.contracts_balances, contract.as_bytes())
            .map(|res| {
                let bytes = res?;
                let hash = Hash::from_bytes(&bytes[HASH_SIZE..])?;
                Ok(hash)
            })
        )
    }

    async fn get_last_topoheight_for_contract_balance(&self, contract: &Hash, asset: &Hash) -> Result<Option<TopoHeight>, BlockchainError> {
        trace!("get last topoheight for contract {} balance {}", contract, asset);
        self.load_optional_from_disk(&self.contracts_balances, &Self::get_contract_balance_key(contract, asset))
    }

    async fn get_last_contract_balance(&self, contract: &Hash, asset: &Hash) -> Result<(TopoHeight, VersionedContractBalance), BlockchainError> {
        trace!("get last contract {} balance {}", contract, asset);
        let Some(topoheight) = self.get_last_topoheight_for_contract_balance(contract, asset).await? else {
            return Err(BlockchainError::NoContractBalance);
        };

        let key = Self::get_versioned_key(Self::get_contract_balance_key(contract, asset), topoheight);
        Ok((topoheight, self.load_from_disk(&self.versioned_contracts_balances, &key, DiskContext::ContractBalance)?))
    }

    async fn set_last_contract_balance_to(&mut self, contract: &Hash, asset: &Hash, topoheight: TopoHeight, balance: VersionedContractBalance) -> Result<(), BlockchainError> {
        trace!("set last contract {} balance {} to topoheight {}", contract, asset, topoheight);
        let key = Self::get_versioned_key(Self::get_contract_balance_key(contract, asset), topoheight);
        Self::insert_into_disk(self.snapshot.as_mut(), &self.versioned_contracts_balances, &key, balance.to_bytes())?;
        Self::insert_into_disk(self.snapshot.as_mut(), &self.contracts_balances, &Self::get_contract_balance_key(contract, asset), &topoheight.to_be_bytes())?;

        Ok(())
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