use std::{borrow::Cow, collections::HashMap};

use async_trait::async_trait;
use curve25519_dalek::{ristretto::CompressedRistretto, traits::Identity};
use indexmap::{IndexMap, IndexSet};
use xelis_vm::ValueCell;

use crate::{
    block::{Block, BlockHeader, BlockVersion, EXTRA_NONCE_SIZE, TopoHeight},
    contract::{
        ChainState,
        ContractEventTracker,
        ContractModule,
        ContractProvider,
        ContractStorage,
        InterContractPermission,
        vm::ContractCaller
    },
    crypto::{Hash, elgamal::CompressedPublicKey}
};

#[derive(Default)]
pub struct MockProvider {
    pub data: HashMap<(Hash, ValueCell), (TopoHeight, Option<ValueCell>)>,
}

#[async_trait]
impl ContractStorage for MockProvider {
    async fn load_data(&self, contract: &Hash, key: &ValueCell, _: TopoHeight) -> Result<Option<(TopoHeight, Option<ValueCell>)>, anyhow::Error> {
        Ok(self.data.get(&(contract.clone(), key.clone())).cloned())
    }

    async fn load_data_latest_topoheight(&self, contract: &Hash, key: &ValueCell, _: TopoHeight) -> Result<Option<TopoHeight>, anyhow::Error> {
        Ok(self.data.get(&(contract.clone(), key.clone())).map(|(topo, _)| *topo))
    }

    async fn has_contract(&self, contract: &Hash, _: TopoHeight) -> Result<bool, anyhow::Error> {
        Ok(self.data.keys().any(|(c, _)| c == contract))
    }
}

#[async_trait]
impl ContractProvider for MockProvider {
    async fn get_contract_balance_for_asset(&self, _: &Hash, _: &Hash, _: TopoHeight) -> Result<Option<(TopoHeight, u64)>, anyhow::Error> {
        Ok(None)
    }

    async fn get_account_balance_for_asset(&self, _: &crate::crypto::PublicKey, _: &Hash, _: TopoHeight) -> Result<Option<(TopoHeight, crate::account::CiphertextCache)>, anyhow::Error> {
        Ok(None)
    }

    async fn has_scheduled_execution_at_topoheight(&self, _: &Hash, _: TopoHeight) -> Result<bool, anyhow::Error> {
        Ok(false)
    }

    async fn asset_exists(&self, _: &Hash, _: TopoHeight) -> Result<bool, anyhow::Error> {
        Ok(false)
    }

    async fn load_asset_data(&self, _: &Hash, _: TopoHeight) -> Result<Option<(TopoHeight, crate::asset::AssetData)>, anyhow::Error> {
        Ok(None)
    }

    async fn load_asset_circulating_supply(&self, _: &Hash, _: TopoHeight) -> Result<(TopoHeight, u64), anyhow::Error> {
        Ok((0, 0))
    }

    async fn account_exists(&self, _: &crate::crypto::PublicKey, _: TopoHeight) -> Result<bool, anyhow::Error> {
        Ok(false)
    }

    async fn load_contract_module(&self, _: &Hash, _: TopoHeight) -> Result<Option<ContractModule>, anyhow::Error> {
        Ok(None)
    }
}

pub fn test_chain_state(contract: Hash) -> ChainState<'static> {
    let block_hash = Box::leak(Box::new(Hash::zero()));
    let header = BlockHeader::new(
        BlockVersion::V3,
        0,
        0,
        IndexSet::new(),
        [0u8; EXTRA_NONCE_SIZE],
        CompressedPublicKey::new(CompressedRistretto::identity()),
        IndexSet::new(),
    );
    let block = Box::leak(Box::new(Block::new(header, Vec::new())));
    let global_caches = Box::leak(Box::new(HashMap::new()));

    ChainState {
        debug_mode: false,
        mainnet: true,
        entry_contract: Cow::Owned(contract.clone()),
        topoheight: 1,
        block_hash,
        block,
        caller: ContractCaller::Scheduled(Cow::Owned(Hash::zero()), Cow::Owned(contract.clone())),
        caches: HashMap::new(),
        modules: HashMap::new(),
        outputs: Vec::new(),
        tracker: ContractEventTracker::default(),
        global_caches,
        assets: HashMap::new(),
        injected_gas: IndexMap::new(),
        scheduled_executions: IndexMap::new(),
        allow_executions: true,
        permission: Cow::Owned(InterContractPermission::default()),
    }
}
