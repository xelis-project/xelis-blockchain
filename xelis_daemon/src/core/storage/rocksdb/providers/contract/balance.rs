use async_trait::async_trait;
use rocksdb::Direction;
use log::trace;
use xelis_common::{
    block::TopoHeight,
    crypto::Hash, serializer::Skip
};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::{AssetId, Column, ContractId, IteratorMode},
        ContractBalanceProvider,
        RocksStorage,
        VersionedContractBalance
    }
};

#[async_trait]
impl ContractBalanceProvider for RocksStorage {
    // Check if a balance exists for asset and contract
    async fn has_contract_balance_for(&self, contract: &Hash, asset: &Hash) -> Result<bool, BlockchainError> {
        trace!("has contract {} balance for {}", contract, asset);
        let contract_id = self.get_contract_id(contract)?;
        let asset_id = self.get_asset_id(asset)?;

        self.contains_data(Column::ContractsBalances, &Self::get_contract_balance_key(contract_id, asset_id))
    }

    // Check if a balance exists for asset and contract at specific topoheight
    async fn has_contract_balance_at_exact_topoheight(&self, contract: &Hash, asset: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("has contract {} balance at exact topoheight {} for {}", contract, topoheight, asset);
        let contract_id = self.get_contract_id(contract)?;
        let asset_id = self.get_asset_id(asset)?;

        self.contains_data(Column::VersionedContractsBalances, &Self::get_versioned_contract_balance_key(contract_id, asset_id, topoheight))
    }

    // Get the balance at a specific topoheight for asset and contract
    async fn get_contract_balance_at_exact_topoheight(&self, contract: &Hash, asset: &Hash, topoheight: TopoHeight) -> Result<VersionedContractBalance, BlockchainError> {
        trace!("get contract {} balance at exact topoheight {} for {}", contract, topoheight, asset);
        let contract_id = self.get_contract_id(contract)?;
        let asset_id = self.get_asset_id(asset)?;

        self.load_from_disk(Column::VersionedContractsBalances, &Self::get_versioned_contract_balance_key(contract_id, asset_id, topoheight))
    }

    // Get the balance under or equal topoheight requested for asset and contract
    async fn get_contract_balance_at_maximum_topoheight(&self, contract: &Hash, asset: &Hash, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedContractBalance)>, BlockchainError> {
        trace!("get contract {} balance at maximum topoheight {} for {}", contract, maximum_topoheight, asset);
        let contract_id = self.get_contract_id(contract)?;
        let asset_id = self.get_asset_id(asset)?;

        let key = Self::get_contract_balance_key(contract_id, asset_id);
        let mut prev_topo = self.load_optional_from_disk(Column::ContractsBalances, &key)?;
        while let Some(topo) = prev_topo {
            let key = Self::get_versioned_contract_balance_key(contract_id, asset_id, topo);
            if topo <= maximum_topoheight {
                let version = self.load_from_disk(Column::VersionedContractsBalances, &key)?;
                return Ok(Some((topo, version)))
            }

            prev_topo = self.load_from_disk(Column::VersionedContractsBalances, &key)?;
        }

        Ok(None)
    }

    // Get the last topoheight that the contract has a balance
    async fn get_last_topoheight_for_contract_balance(&self, contract: &Hash, asset: &Hash) -> Result<Option<TopoHeight>, BlockchainError> {
        trace!("get last topoheight for contract {} balance {}", contract, asset);
        let contract_id = self.get_contract_id(contract)?;
        let asset_id = self.get_asset_id(asset)?;

        self.load_optional_from_disk(Column::ContractsBalances, &Self::get_contract_balance_key(contract_id, asset_id))
    }

    // Get the latest topoheight & versioned data for a contract balance
    async fn get_last_contract_balance(&self, contract: &Hash, asset: &Hash) -> Result<(TopoHeight, VersionedContractBalance), BlockchainError> {
        trace!("get last contract {} balance {}", contract, asset);
        let contract_id = self.get_contract_id(contract)?;
        let asset_id = self.get_asset_id(asset)?;

        let key = Self::get_contract_balance_key(contract_id, asset_id);
        let pointer = self.load_from_disk(Column::ContractsBalances, &key[8..])?;

        let versioned_key = Self::get_versioned_contract_balance_key(contract_id, asset_id, pointer);
        let version = self.load_from_disk(Column::VersionedContractsBalances, &versioned_key)?;

        Ok((pointer, version))
    }

    // Get all the contract balances assets
    async fn get_contract_assets_for<'a>(&'a self, contract: &'a Hash) -> Result<impl Iterator<Item = Result<Hash, BlockchainError>> + 'a, BlockchainError> {
        trace!("get contract {} assets", contract);
        self.iter_keys::<Skip<8, AssetId>>(Column::ContractsBalances, IteratorMode::WithPrefix(contract.as_bytes(), Direction::Forward))
            .map(|iter| iter.map(|res| {
                let k = res?;
                self.get_asset_hash_from_id(k.0)
            }))
    }

    // Set the last balance for asset and contract at specific topoheight
    async fn set_last_contract_balance_to(&mut self, contract: &Hash, asset: &Hash, topoheight: TopoHeight, balance: VersionedContractBalance) -> Result<(), BlockchainError> {
        trace!("set last contract {} balance {} to {}", contract, asset, topoheight);
        let contract_id = self.get_contract_id(contract)?;
        let asset_id = self.get_asset_id(asset)?;

        let key = Self::get_versioned_contract_balance_key(contract_id, asset_id, topoheight);
        self.insert_into_disk(Column::ContractsBalances, &key[8..], &topoheight.to_be_bytes())?;
        self.insert_into_disk(Column::VersionedContractsBalances, &key, &balance)
    }
}

impl RocksStorage {
    pub fn get_contract_balance_key(contract: ContractId, asset: AssetId) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(&contract.to_be_bytes());
        buf[8..16].copy_from_slice(&asset.to_be_bytes());

        buf
    }

    pub fn get_versioned_contract_balance_key(contract: ContractId, asset: AssetId, topoheight: TopoHeight) -> [u8; 24] {
        let mut buf = [0u8; 24];
        buf[0..8].copy_from_slice(&topoheight.to_be_bytes());
        buf[8..16].copy_from_slice(&contract.to_be_bytes());
        buf[16..24].copy_from_slice(&asset.to_be_bytes());

        buf
    }
}