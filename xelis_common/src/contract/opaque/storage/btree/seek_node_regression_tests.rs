use super::*;

use async_trait::async_trait;
use curve25519_dalek::{
    ristretto::CompressedRistretto,
    traits::Identity,
};
use indexmap::{IndexMap, IndexSet};
use std::{
    borrow::Cow,
    collections::HashMap,
    sync::Arc,
};

use crate::{
    block::{Block, BlockHeader, BlockVersion, TopoHeight, EXTRA_NONCE_SIZE},
    contract::{
        cache::{AssetChanges, ContractCache},
        contract_log::ContractLog,
        module::ContractModule,
        permission::InterContractPermission,
        scheduled_execution::ScheduledExecution,
        vm::ContractCaller,
        ContractEventTracker,
        ContractStorage,
    },
    crypto::{
        Hash,
        elgamal::CompressedPublicKey,
    },
    transaction::Transaction,
};

/// Minimal mock identical to the one in the other test module, but scoped here
/// so this module can be appended without touching the existing one.
#[derive(Default)]
struct MockProvider {
    data: HashMap<(Hash, ValueCell), (TopoHeight, Option<ValueCell>)>,
}

#[async_trait]
impl ContractStorage for MockProvider {
    async fn load_data(
        &self,
        contract: &Hash,
        key: &ValueCell,
        _: TopoHeight
    ) -> Result<Option<(TopoHeight, Option<ValueCell>)>, anyhow::Error> {
        Ok(self.data.get(&(contract.clone(), key.clone())).cloned())
    }

    async fn load_data_latest_topoheight(
        &self,
        contract: &Hash,
        key: &ValueCell,
        _: TopoHeight
    ) -> Result<Option<TopoHeight>, anyhow::Error> {
        Ok(self.data.get(&(contract.clone(), key.clone())).map(|(topo, _)| *topo))
    }

    async fn has_contract(&self, contract: &Hash, _: TopoHeight) -> Result<bool, anyhow::Error> {
        Ok(self.data.keys().any(|(c, _)| c == contract))
    }
}

#[async_trait]
impl ContractProvider for MockProvider {
    async fn get_contract_balance_for_asset(
        &self, _: &Hash, _: &Hash, _: TopoHeight
    ) -> Result<Option<(TopoHeight, u64)>, anyhow::Error> {
        Ok(None)
    }

    async fn get_account_balance_for_asset(
        &self, _: &crate::crypto::PublicKey, _: &Hash, _: TopoHeight
    ) -> Result<Option<(TopoHeight, crate::account::CiphertextCache)>, anyhow::Error> {
        Ok(None)
    }

    async fn has_scheduled_execution_at_topoheight(
        &self, _: &Hash, _: TopoHeight
    ) -> Result<bool, anyhow::Error> {
        Ok(false)
    }

    async fn asset_exists(&self, _: &Hash, _: TopoHeight) -> Result<bool, anyhow::Error> {
        Ok(false)
    }

    async fn load_asset_data(
        &self, _: &Hash, _: TopoHeight
    ) -> Result<Option<(TopoHeight, crate::asset::AssetData)>, anyhow::Error> {
        Ok(None)
    }

    async fn load_asset_circulating_supply(
        &self, _: &Hash, _: TopoHeight
    ) -> Result<(TopoHeight, u64), anyhow::Error> {
        Ok((0, 0))
    }

    async fn account_exists(
        &self, _: &crate::crypto::PublicKey, _: TopoHeight
    ) -> Result<bool, anyhow::Error> {
        Ok(false)
    }

    async fn load_contract_module(
        &self, _: &Hash, _: TopoHeight
    ) -> Result<Option<ContractModule>, anyhow::Error> {
        Ok(None)
    }
}

fn test_chain_state(contract: Hash) -> ChainState<'static> {
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
    let block = Box::leak(Box::new(Block::new(header, Vec::<Arc<Transaction>>::new())));
    let global_caches = Box::leak(Box::new(HashMap::<Hash, ContractCache>::new()));

    ChainState {
        debug_mode: false,
        mainnet: true,
        entry_contract: Cow::Owned(contract.clone()),
        topoheight: 1,
        block_hash,
        block,
        caller: ContractCaller::Scheduled(Cow::Owned(Hash::zero()), Cow::Owned(contract.clone())),
        caches: HashMap::<Hash, ContractCache>::new(),
        modules: HashMap::<Hash, Option<ContractModule>>::new(),
        outputs: Vec::<ContractLog>::new(),
        tracker: ContractEventTracker::default(),
        global_caches,
        assets: HashMap::<Hash, Option<AssetChanges>>::new(),
        injected_gas: IndexMap::new(),
        executions_topoheight: HashMap::<TopoHeight, IndexSet<ScheduledExecution>>::new(),
        executions_block_end: IndexSet::<ScheduledExecution>::new(),
        allow_executions: true,
        permission: Cow::Owned(InterContractPermission::default()),
    }
}

async fn insert_key(
    provider: &MockProvider,
    state: &mut ChainState<'_>,
    contract: &Hash,
    store: &OpaqueBTreeStore,
    key: Vec<u8>,
    value: ValueCell,
) -> Result<Option<ValueCell>, EnvironmentError> {
    let mut ctx = TreeContext::new(provider, state, contract, &store.namespace);
    super::insert_key(&mut ctx, key, value).await
}

async fn seek_node(
    provider: &MockProvider,
    state: &mut ChainState<'_>,
    contract: &Hash,
    store: &OpaqueBTreeStore,
    key: &[u8],
    bias: BTreeSeekBias,
) -> Result<Option<Node>, EnvironmentError> {
    let mut ctx = TreeContext::new(provider, state, contract, &store.namespace);
    super::seek_node(&mut ctx, key, bias).await
}

#[tokio::test(flavor = "current_thread")]
async fn btree_seek_equal_strict_bias_uses_ancestors() {
    // Shape:     20
    //           /  \
    //         10    30
    //              /
    //             25
    //
    // For key==25:
    //   - Greater  -> 30 (ancestor path)
    //   - Less     -> 20 (ancestor path)
    // For edges:
    //   - key==30, Greater -> None
    //   - key==10, Less    -> None
    let contract = Hash::zero();
    let provider = MockProvider::default();
    let mut state = test_chain_state(contract.clone());
    let store = OpaqueBTreeStore { namespace: b"seek_equal".to_vec() };

    for (k, v) in [20u64, 10, 30, 25].into_iter().map(|k| (k, k * 10)) {
        insert_key(
            &provider,
            &mut state,
            &contract,
            &store,
            k.to_be_bytes().to_vec(),
            ValueCell::from(Primitive::U64(v)),
        ).await.unwrap();
    }

    // Strict Greater on exact hit with no right subtree must use ancestor
    let gt = seek_node(
        &provider,
        &mut state,
        &contract,
        &store,
        &25u64.to_be_bytes(),
        BTreeSeekBias::Greater,
    ).await.unwrap();
    assert_eq!(gt.unwrap().value.as_u64().unwrap(), 300);

    // Strict Less on exact hit with no left subtree must use ancestor
    let lt = seek_node(
        &provider,
        &mut state,
        &contract,
        &store,
        &25u64.to_be_bytes(),
        BTreeSeekBias::Less,
    ).await.unwrap();
    assert_eq!(lt.unwrap().value.as_u64().unwrap(), 200);

    // Edge: max element, Greater -> None
    let gt_max = seek_node(
        &provider,
        &mut state,
        &contract,
        &store,
        &30u64.to_be_bytes(),
        BTreeSeekBias::Greater,
    ).await.unwrap();
    assert!(gt_max.is_none());

    // Edge: min element, Less -> None
    let lt_min = seek_node(
        &provider,
        &mut state,
        &contract,
        &store,
        &10u64.to_be_bytes(),
        BTreeSeekBias::Less,
    ).await.unwrap();
    assert!(lt_min.is_none());
}

