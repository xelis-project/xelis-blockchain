use async_trait::async_trait;
use futures::{stream, Stream, StreamExt};
use log::trace;
use xelis_common::{
    block::TopoHeight,
    crypto::{hash, Hash},
    serializer::Serializer,
};
use xelis_vm::ValueCell;
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::{ContractDataProvider, SledStorage, VersionedContractData}
};

#[async_trait]
impl ContractDataProvider for SledStorage {
    async fn set_last_contract_data_to(&mut self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight, data: &VersionedContractData) -> Result<(), BlockchainError> {
        trace!("set last contract data to topoheight {}", topoheight);
        let versioned_key = self.get_versioned_contract_data_key(contract, key, topoheight);
        Self::insert_into_disk(self.snapshot.as_mut(), &self.versioned_contracts_data, &versioned_key, data.to_bytes())?;

        let hash = self.get_contract_data_key(key, contract);
        Self::insert_into_disk(self.snapshot.as_mut(), &self.contracts_data, hash.as_bytes(), &topoheight.to_be_bytes())?;

        Ok(())
    }

    async fn get_last_topoheight_for_contract_data(&self, contract: &Hash, key: &ValueCell) -> Result<Option<TopoHeight>, BlockchainError> {
        trace!("get last topoheight for contract data");
        let hash = self.get_contract_data_key(key, contract);
        self.load_optional_from_disk(&self.contracts_data, hash.as_bytes())
    }

    async fn get_contract_data_at_exact_topoheight_for<'a>(&self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight) -> Result<VersionedContractData, BlockchainError> {
        trace!("get contract data at topoheight {}", topoheight);
        self.load_from_disk(&self.versioned_contracts_data, &self.get_versioned_contract_data_key(contract, key, topoheight), DiskContext::ContractData)
    }

    async fn get_contract_data_at_maximum_topoheight_for<'a>(&self, contract: &Hash, key: &ValueCell, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedContractData)>, BlockchainError> {
        trace!("get contract data at maximum topoheight {}", maximum_topoheight);
        match self.get_contract_data_topoheight_at_maximum_topoheight_for(contract, key, maximum_topoheight).await? {
            Some(topoheight) => {
                let contract = self.get_contract_data_at_exact_topoheight_for(&contract, key, topoheight).await?;
                Ok(Some((topoheight, contract)))
            },
            None => Ok(None)
        }
    }

    async fn get_contract_data_topoheight_at_maximum_topoheight_for<'a>(&self, contract: &Hash, key: &ValueCell, maximum_topoheight: TopoHeight) -> Result<Option<TopoHeight>, BlockchainError> {
        trace!("get contract data topoheight at maximum topoheight {}", maximum_topoheight);
        let Some(pointer) = self.get_last_topoheight_for_contract_data(contract, key).await? else {
            return Ok(None)
        };

        let topo = if self.has_contract_data_at_exact_topoheight(contract, key, maximum_topoheight).await? {
            maximum_topoheight
        } else {
            pointer
        };

        let mut previous_topo = Some(topo);
        while let Some(topoheight) = previous_topo {
            if topoheight <= maximum_topoheight {
                trace!("Contract data topoheight {} is at maximum topoheight", topoheight);
                return Ok(Some(topoheight))
            }

            previous_topo = self.load_from_disk(
                &self.versioned_contracts_data,
                &self.get_versioned_contract_data_key(&contract, key, topoheight),
                DiskContext::ContractDataTopoHeight
            )?;
        }

        Ok(None)
    }

    async fn has_contract_data_at_maximum_topoheight(&self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("has contract data at topoheight {}", topoheight);
        self.get_contract_data_at_maximum_topoheight_for(contract, key, topoheight).await
            .map(|res| res.map_or(false, |v| v.1.take().is_some()))
    }

    async fn has_contract_data_at_exact_topoheight(&self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("has contract data at exact topoheight {}", topoheight);
        self.contains_data(&self.versioned_contracts_data, &self.get_versioned_contract_data_key(contract, key, topoheight))
    }

    async fn get_contract_data_entries_at_maximum_topoheight<'a>(&'a self, contract: &'a Hash, topoheight: TopoHeight) -> Result<impl Stream<Item = Result<(ValueCell, ValueCell), BlockchainError>> + Send + 'a, BlockchainError> {
        Ok(stream::iter(Self::scan_prefix_keys(self.snapshot.as_ref(), &self.contracts_data, contract.as_bytes()))
            .map(move |res| async move {
                let key = res?;
                let k = ValueCell::from_bytes(&key)?;
                let value = self.get_contract_data_at_maximum_topoheight_for(contract, &k, topoheight).await?;

                Ok(value.and_then(|(_, v)| v.take().map(|v| (k, v))))
            })
            .filter_map(|res| async move { res.await.transpose() })
        )
    }
}

impl SledStorage {
    pub fn get_versioned_contract_data_key(&self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight) -> [u8; 40] {
        let mut buffer = [0u8; 40];
        buffer[..8].copy_from_slice(&topoheight.to_be_bytes());
        buffer[8..].copy_from_slice(self.get_contract_data_key(key, contract).as_bytes());
        buffer
    }

    pub fn get_versioned_contract_data_key_from_hash(&self, hash: &Hash, topoheight: TopoHeight) -> [u8; 40] {
        let mut buffer = [0u8; 40];
        buffer[..8].copy_from_slice(&topoheight.to_be_bytes());
        buffer[8..].copy_from_slice(hash.as_bytes());
        buffer
    }

    pub fn get_contract_data_key(&self, constant: &ValueCell, contract: &Hash) -> Hash {
        hash(&[constant.to_bytes(), contract.to_bytes()].concat())
    }
}