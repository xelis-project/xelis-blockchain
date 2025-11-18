use super::*;

use async_trait::async_trait;
use curve25519_dalek::{
    ristretto::CompressedRistretto,
    traits::Identity,
};
use indexmap::{IndexMap, IndexSet};
use rand::{
    rngs::StdRng,
    Rng,
    SeedableRng,
};
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

#[derive(Default)]
struct MockProvider {
    data: HashMap<(Hash, ValueCell), (TopoHeight, Option<ValueCell>)>,
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

async fn find_key(
    provider: &MockProvider,
    state: &mut ChainState<'_>,
    contract: &Hash,
    store: &OpaqueBTreeStore,
    key: &[u8],
) -> Result<Option<ValueCell>, EnvironmentError> {
    let mut ctx = TreeContext::new(provider, state, contract, &store.namespace);
    super::find_key(&mut ctx, key).await
}

async fn delete_key(
    provider: &MockProvider,
    state: &mut ChainState<'_>,
    contract: &Hash,
    store: &OpaqueBTreeStore,
    key: &[u8],
) -> Result<Option<ValueCell>, EnvironmentError> {
    let mut ctx = TreeContext::new(provider, state, contract, &store.namespace);
    super::delete_key(&mut ctx, key).await
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

async fn read_node(
    provider: &MockProvider,
    state: &mut ChainState<'_>,
    contract: &Hash,
    namespace: &[u8],
    node_id: u64,
) -> Result<Option<Node>, EnvironmentError> {
    let mut ctx = TreeContext::new(provider, state, contract, namespace);
    super::read_node(&mut ctx, node_id).await
}

async fn read_root_id(
    provider: &MockProvider,
    state: &mut ChainState<'_>,
    contract: &Hash,
    namespace: &[u8],
) -> Result<u64, EnvironmentError> {
    let mut ctx = TreeContext::new(provider, state, contract, namespace);
    super::read_root_id(&mut ctx).await
}

async fn successor(
    provider: &MockProvider,
    state: &mut ChainState<'_>,
    contract: &Hash,
    namespace: &[u8],
    node_id: u64,
) -> Result<Option<u64>, EnvironmentError> {
    let mut ctx = TreeContext::new(provider, state, contract, namespace);
    super::successor(&mut ctx, node_id).await
}

async fn find_min_node(
    provider: &MockProvider,
    state: &mut ChainState<'_>,
    contract: &Hash,
    namespace: &[u8],
    node_id: u64,
) -> Result<Node, EnvironmentError> {
    let mut ctx = TreeContext::new(provider, state, contract, namespace);
    super::find_min_node(&mut ctx, node_id).await
}

async fn refresh_cursor_cache(
    cursor: &mut OpaqueBTreeCursor,
    provider: &MockProvider,
    state: &mut ChainState<'_>,
) -> Result<(), EnvironmentError> {
    let contract = cursor.contract.clone();
    let namespace = cursor.namespace.clone();
    let mut ctx = TreeContext::new(provider, state, &contract, &namespace);
    super::refresh_cursor_cache(cursor, &mut ctx).await
}

async fn allocate_node_id(
    provider: &MockProvider,
    state: &mut ChainState<'_>,
    contract: &Hash,
    namespace: &[u8],
) -> Result<u64, EnvironmentError> {
    let mut ctx = TreeContext::new(provider, state, contract, namespace);
    super::allocate_node_id(&mut ctx).await
}

async fn read_next_id(
    provider: &MockProvider,
    state: &mut ChainState<'_>,
    contract: &Hash,
    namespace: &[u8],
) -> Result<u64, EnvironmentError> {
    let mut ctx = TreeContext::new(provider, state, contract, namespace);
    super::read_next_id(&mut ctx).await
}

#[tokio::test(flavor = "current_thread")]
async fn btree_insert_get_delete_roundtrip() {
    let contract = Hash::zero();
    let provider = MockProvider::default();
    let mut state = test_chain_state(contract.clone());
    let store = OpaqueBTreeStore { namespace: b"orders".to_vec() };

    assert!(find_key(&provider, &mut state, &contract, &store, b"k1").await.unwrap().is_none());

    insert_key(&provider, &mut state, &contract, &store, b"k1".to_vec(), ValueCell::from(Primitive::U64(10))).await.unwrap();
    insert_key(&provider, &mut state, &contract, &store, b"k2".to_vec(), ValueCell::from(Primitive::U64(20))).await.unwrap();

    let val = find_key(&provider, &mut state, &contract, &store, b"k1").await.unwrap();
    assert_eq!(val.unwrap().as_u64().unwrap(), 10);

    let removed = delete_key(&provider, &mut state, &contract, &store, b"k1").await.unwrap();
    assert_eq!(removed.unwrap().as_u64().unwrap(), 10);
    assert!(find_key(&provider, &mut state, &contract, &store, b"k1").await.unwrap().is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn btree_seek_biases_work() {
    let contract = Hash::zero();
    let provider = MockProvider::default();
    let mut state = test_chain_state(contract.clone());
    let store = OpaqueBTreeStore { namespace: b"book".to_vec() };

    for (k, v) in &[(10u64, 100u64), (20, 200), (30, 300)] {
        insert_key(
            &provider,
            &mut state,
            &contract,
            &store,
            k.to_be_bytes().to_vec(),
            ValueCell::from(Primitive::U64(*v)),
        ).await.unwrap();
    }

    let ge = seek_node(&provider, &mut state, &contract, &store, &25u64.to_be_bytes(), BTreeSeekBias::GreaterOrEqual).await.unwrap();
    assert_eq!(ge.unwrap().value.as_u64().unwrap(), 300);

    let le = seek_node(&provider, &mut state, &contract, &store, &25u64.to_be_bytes(), BTreeSeekBias::LessOrEqual).await.unwrap();
    assert_eq!(le.unwrap().value.as_u64().unwrap(), 200);

    let lt = seek_node(&provider, &mut state, &contract, &store, &10u64.to_be_bytes(), BTreeSeekBias::Less).await.unwrap();
    assert!(lt.is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn btree_cursor_iteration_matches_ordering() {
    let contract = Hash::zero();
    let provider = MockProvider::default();
    let mut state = test_chain_state(contract.clone());
    let store = OpaqueBTreeStore { namespace: b"iter".to_vec() };

    for key in [5u64, 15, 25] {
        insert_key(
            &provider,
            &mut state,
            &contract,
            &store,
            key.to_be_bytes().to_vec(),
            ValueCell::from(Primitive::U64(key)),
        ).await.unwrap();
    }

    let mut current = seek_node(
        &provider,
        &mut state,
        &contract,
        &store,
        &0u64.to_be_bytes(),
        BTreeSeekBias::GreaterOrEqual,
    ).await.unwrap().map(|node| node.id);
    let mut order = Vec::new();
    while let Some(id) = current {
        let node = read_node(&provider, &mut state, &contract, &store.namespace, id).await.unwrap().unwrap();
        order.push(node.value.as_u64().unwrap());
        current = successor(&provider, &mut state, &contract, &store.namespace, id).await.unwrap();
    }

    assert_eq!(order, vec![5, 15, 25]);
}

#[tokio::test(flavor = "current_thread")]
async fn btree_cursor_scans_random_u64s_in_order() {
    let contract = Hash::zero();
    let provider = MockProvider::default();
    let mut state = test_chain_state(contract.clone());
    let store = OpaqueBTreeStore { namespace: b"rand_cursor_scan".to_vec() };

    let mut rng = StdRng::seed_from_u64(0x5EED_5EED);
    let mut entries = IndexMap::new();
    while entries.len() < 100 {
        let key = rng.gen::<u64>();
        if entries.contains_key(&key) {
            continue;
        }
        let value = rng.gen::<u64>();
        entries.insert(key, value);
        insert_key(
            &provider,
            &mut state,
            &contract,
            &store,
            key.to_be_bytes().to_vec(),
            ValueCell::from(Primitive::U64(value)),
        ).await.unwrap();
    }

    let mut sorted: Vec<(u64, u64)> = entries.into_iter().collect();
    sorted.sort_by_key(|(key, _)| *key);

    let start_node = seek_node(
        &provider,
        &mut state,
        &contract,
        &store,
        &0u64.to_be_bytes(),
        BTreeSeekBias::GreaterOrEqual,
    ).await.unwrap().expect("cursor start");

    let mut key_bytes = [0u8; 8];
    key_bytes.copy_from_slice(&start_node.key);
    assert_eq!(u64::from_be_bytes(key_bytes), sorted[0].0);

    let mut cursor = OpaqueBTreeCursor {
        contract: contract.clone(),
        namespace: store.namespace.clone(),
        current_node: Some(start_node.id),
        cached_key: Some(start_node.key.clone()),
        cached_value: Some(start_node.value.clone()),
    };

    let mut observed = Vec::new();
    while let Some(current_id) = cursor.current_node {
        refresh_cursor_cache(&mut cursor, &provider, &mut state).await.unwrap();
        let cached_key = cursor.cached_key.as_ref().expect("cached key");
        let mut arr = [0u8; 8];
        arr.copy_from_slice(cached_key);
        let key = u64::from_be_bytes(arr);
        let value = cursor.cached_value.as_ref().expect("cached value").as_u64().unwrap();
        observed.push((key, value));
        cursor.current_node = successor(&provider, &mut state, &contract, &store.namespace, current_id).await.unwrap();
    }

    assert_eq!(observed.len(), sorted.len());
    assert_eq!(observed, sorted);
}

#[tokio::test(flavor = "current_thread")]
async fn btree_allows_duplicate_keys_and_ordered_traversal() {
    let contract = Hash::zero();
    let provider = MockProvider::default();
    let mut state = test_chain_state(contract.clone());
    let store = OpaqueBTreeStore { namespace: b"dup_keys".to_vec() };

    let key_bytes = 7u64.to_be_bytes().to_vec();
    for value in [100u64, 200, 300] {
        insert_key(
            &provider,
            &mut state,
            &contract,
            &store,
            key_bytes.clone(),
            ValueCell::from(Primitive::U64(value)),
        ).await.unwrap();
    }

    let first = find_key(&provider, &mut state, &contract, &store, &key_bytes).await.unwrap().unwrap();
    assert_eq!(first.as_u64().unwrap(), 100);

    assert_eq!(
        collect_values_in_order(&provider, &mut state, &contract, &store.namespace).await,
        vec![100, 200, 300]
    );

    for expected in [100u64, 200, 300] {
        let removed = delete_key(&provider, &mut state, &contract, &store, &key_bytes).await.unwrap();
        assert_eq!(removed.unwrap().as_u64().unwrap(), expected);
    }

    assert!(find_key(&provider, &mut state, &contract, &store, &key_bytes).await.unwrap().is_none());
    assert_eq!(read_root_id(&provider, &mut state, &contract, &store.namespace).await.unwrap(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn btree_cursor_scans_duplicate_bucket() {
    let contract = Hash::zero();
    let provider = MockProvider::default();
    let mut state = test_chain_state(contract.clone());
    let store = OpaqueBTreeStore { namespace: b"dup_scan".to_vec() };

    let key_bytes = 9u64.to_be_bytes().to_vec();
    for value in [11u64, 22, 33] {
        insert_key(
            &provider,
            &mut state,
            &contract,
            &store,
            key_bytes.clone(),
            ValueCell::from(Primitive::U64(value)),
        ).await.unwrap();
    }

    let first = seek_node(
        &provider,
        &mut state,
        &contract,
        &store,
        &key_bytes,
        BTreeSeekBias::Exact,
    ).await.unwrap().expect("first duplicate");

    let mut cursor = OpaqueBTreeCursor {
        contract: contract.clone(),
        namespace: store.namespace.clone(),
        current_node: Some(first.id),
        cached_key: Some(first.key.clone()),
        cached_value: Some(first.value.clone()),
    };

    let mut observed = Vec::new();
    loop {
        refresh_cursor_cache(&mut cursor, &provider, &mut state).await.unwrap();
        let Some(current_id) = cursor.current_node else { break; };
        let value = cursor.cached_value.as_ref().unwrap().as_u64().unwrap();
        observed.push(value);

        let next_id = successor(&provider, &mut state, &contract, &store.namespace, current_id).await.unwrap();
        let Some(next_id) = next_id else { break; };
        let next_node = read_node(&provider, &mut state, &contract, &store.namespace, next_id).await.unwrap().unwrap();
        if next_node.key != key_bytes {
            break;
        }
        cursor.current_node = Some(next_id);
        cursor.cached_key = Some(next_node.key.clone());
        cursor.cached_value = Some(next_node.value.clone());
    }

    assert_eq!(observed, vec![11, 22, 33]);
}

#[tokio::test(flavor = "current_thread")]
async fn btree_delete_root_with_two_children_promotes_successor() {
    let contract = Hash::zero();
    let provider = MockProvider::default();
    let mut state = test_chain_state(contract.clone());
    let store = OpaqueBTreeStore { namespace: b"delete_root".to_vec() };

    for key in [40u64, 20, 60, 50] {
        insert_key(
            &provider,
            &mut state,
            &contract,
            &store,
            key.to_be_bytes().to_vec(),
            ValueCell::from(Primitive::U64(key * 10)),
        ).await.unwrap();
    }

    let removed = delete_key(
        &provider,
        &mut state,
        &contract,
        &store,
        &40u64.to_be_bytes(),
    ).await.unwrap();
    assert_eq!(removed.unwrap().as_u64().unwrap(), 400);
    assert!(find_key(&provider, &mut state, &contract, &store, &40u64.to_be_bytes()).await.unwrap().is_none());

    let root_id = read_root_id(&provider, &mut state, &contract, &store.namespace).await.unwrap();
    let root = read_node(&provider, &mut state, &contract, &store.namespace, root_id).await.unwrap().unwrap();
    assert_eq!(root.key, 50u64.to_be_bytes().to_vec());
    assert_eq!(root.value.as_u64().unwrap(), 500);

    // Remaining nodes still searchable
    assert_eq!(
        find_key(&provider, &mut state, &contract, &store, &50u64.to_be_bytes()).await.unwrap()
            .unwrap()
            .as_u64()
            .unwrap(),
        500
    );
}

#[tokio::test(flavor = "current_thread")]
async fn btree_seek_handles_missing_key_biases() {
    let contract = Hash::zero();
    let provider = MockProvider::default();
    let mut state = test_chain_state(contract.clone());
    let store = OpaqueBTreeStore { namespace: b"seek_biases".to_vec() };

    for key in [10u64, 30, 40] {
        insert_key(
            &provider,
            &mut state,
            &contract,
            &store,
            key.to_be_bytes().to_vec(),
            ValueCell::from(Primitive::U64(key * 100)),
        ).await.unwrap();
    }

    let target = 25u64.to_be_bytes();
    let ge = seek_node(&provider, &mut state, &contract, &store, &target, BTreeSeekBias::GreaterOrEqual).await.unwrap();
    assert_eq!(ge.unwrap().value.as_u64().unwrap(), 3000);

    let le = seek_node(&provider, &mut state, &contract, &store, &target, BTreeSeekBias::LessOrEqual).await.unwrap();
    assert_eq!(le.unwrap().value.as_u64().unwrap(), 1000);

    let gt = seek_node(&provider, &mut state, &contract, &store, &40u64.to_be_bytes(), BTreeSeekBias::Greater).await.unwrap();
    assert!(gt.is_none());

    let lt = seek_node(&provider, &mut state, &contract, &store, &10u64.to_be_bytes(), BTreeSeekBias::Less).await.unwrap();
    assert!(lt.is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn btree_cursor_key_value_and_exhaustion() {
    let contract = Hash::zero();
    let provider = MockProvider::default();
    let mut state = test_chain_state(contract.clone());
    let store = OpaqueBTreeStore { namespace: b"cursor_access".to_vec() };

    for key in [2u64, 4, 6] {
        insert_key(
            &provider,
            &mut state,
            &contract,
            &store,
            key.to_be_bytes().to_vec(),
            ValueCell::from(Primitive::U64(key * 5)),
        ).await.unwrap();
    }

    let cursor = seek_node(
        &provider,
        &mut state,
        &contract,
        &store,
        &4u64.to_be_bytes(),
        BTreeSeekBias::Exact,
    ).await.unwrap().expect("cursor");

    let mut cursor = OpaqueBTreeCursor {
        contract: contract.clone(),
        namespace: store.namespace.clone(),
        current_node: Some(cursor.id),
        cached_key: Some(cursor.key.clone()),
        cached_value: Some(cursor.value.clone()),
    };

    // Key/value come from cached data
    assert_eq!(cursor.cached_key.as_ref().unwrap(), &4u64.to_be_bytes().to_vec());
    assert_eq!(cursor.cached_value.as_ref().unwrap().as_u64().unwrap(), 20);

    cursor.cached_key = None;
    cursor.cached_value = None;
    refresh_cursor_cache(&mut cursor, &provider, &mut state).await.unwrap();
    assert_eq!(cursor.cached_value.as_ref().unwrap().as_u64().unwrap(), 20);

    cursor.current_node = successor(&provider, &mut state, &contract, &store.namespace, cursor.current_node.unwrap()).await.unwrap();
    refresh_cursor_cache(&mut cursor, &provider, &mut state).await.unwrap();
    assert_eq!(cursor.cached_value.as_ref().unwrap().as_u64().unwrap(), 30);

    assert!(cursor.cached_key.is_some());

    cursor.current_node = successor(&provider, &mut state, &contract, &store.namespace, cursor.current_node.unwrap()).await.unwrap();
    refresh_cursor_cache(&mut cursor, &provider, &mut state).await.unwrap();
    assert!(cursor.cached_key.is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn btree_cursor_allows_deleting_during_scan() {
    let contract = Hash::zero();
    let provider = MockProvider::default();
    let mut state = test_chain_state(contract.clone());
    let store = OpaqueBTreeStore { namespace: b"scan_delete".to_vec() };

    for key in [10u64, 20, 30] {
        insert_key(
            &provider,
            &mut state,
            &contract,
            &store,
            key.to_be_bytes().to_vec(),
            ValueCell::from(Primitive::U64(key)),
        ).await.unwrap();
    }

    let cursor_node = seek_node(
        &provider,
        &mut state,
        &contract,
        &store,
        &0u64.to_be_bytes(),
        BTreeSeekBias::GreaterOrEqual,
    ).await.unwrap().expect("seek node");

    let mut cursor = OpaqueBTreeCursor {
        contract: contract.clone(),
        namespace: store.namespace.clone(),
        current_node: Some(cursor_node.id),
        cached_key: Some(cursor_node.key.clone()),
        cached_value: Some(cursor_node.value.clone()),
    };

    let mut outputs = Vec::new();
    loop {
        if let Some(key) = cursor.cached_key.clone() {
            outputs.push(u64::from_be_bytes(key[..8].try_into().unwrap()));
            delete_key(&provider, &mut state, &contract, &store, &key).await.unwrap();
        }

        refresh_cursor_cache(&mut cursor, &provider, &mut state).await.unwrap();
        let Some(current_id) = cursor.current_node else {
            break;
        };

        cursor.current_node = successor(&provider, &mut state, &contract, &store.namespace, current_id).await.unwrap();
        refresh_cursor_cache(&mut cursor, &provider, &mut state).await.unwrap();
    }

    assert_eq!(outputs, vec![10]);
    assert!(cursor.current_node.is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn btree_cursor_deletes_all_keys_during_scan() {
    let contract = Hash::zero();
    let provider = MockProvider::default();
    let mut state = test_chain_state(contract.clone());
    let store = OpaqueBTreeStore { namespace: b"scan_delete_all".to_vec() };

    let mut rng = StdRng::seed_from_u64(0xD3_1E7E);
    let mut keys = IndexSet::new();
    while keys.len() < 100 {
        keys.insert(rng.gen::<u64>());
    }
    for key in keys.iter().copied() {
        insert_key(
            &provider,
            &mut state,
            &contract,
            &store,
            key.to_be_bytes().to_vec(),
            ValueCell::from(Primitive::U64(key)),
        ).await.unwrap();
    }

    let cursor_node = seek_node(
        &provider,
        &mut state,
        &contract,
        &store,
        &0u64.to_be_bytes(),
        BTreeSeekBias::GreaterOrEqual,
    ).await.unwrap().expect("at least one node");

    let mut cursor = OpaqueBTreeCursor {
        contract: contract.clone(),
        namespace: store.namespace.clone(),
        current_node: Some(cursor_node.id),
        cached_key: Some(cursor_node.key.clone()),
        cached_value: Some(cursor_node.value.clone()),
    };

    let mut deleted = Vec::new();
    loop {
        refresh_cursor_cache(&mut cursor, &provider, &mut state).await.unwrap();
        let Some(current_id) = cursor.current_node else {
            break;
        };

        let key_bytes = cursor.cached_key.as_ref().expect("cached key").clone();
        let mut key_arr = [0u8; 8];
        key_arr.copy_from_slice(&key_bytes);
        let key = u64::from_be_bytes(key_arr);

        let next_id = successor(&provider, &mut state, &contract, &store.namespace, current_id).await.unwrap();
        delete_key(&provider, &mut state, &contract, &store, &key_bytes).await.unwrap();

        deleted.push(key);
        cursor.current_node = next_id;
        cursor.cached_key = None;
        cursor.cached_value = None;
    }

    assert_eq!(deleted.len(), keys.len());
    assert_eq!(deleted.iter().copied().collect::<IndexSet<_>>().len(), keys.len());
    assert_eq!(read_root_id(&provider, &mut state, &contract, &store.namespace).await.unwrap(), 0);
    assert!(collect_values_in_order(&provider, &mut state, &contract, &store.namespace).await.is_empty());
}

async fn collect_values_in_order(
    provider: &MockProvider,
    state: &mut ChainState<'_>,
    contract: &Hash,
    namespace: &[u8],
) -> Vec<u64> {
    let root = read_root_id(provider, state, contract, namespace).await.unwrap();
    if root == 0 {
        return vec![];
    }

    let start = find_min_node(provider, state, contract, namespace, root).await.unwrap();
    let mut values = Vec::new();
    let mut current = Some(start.id);
    while let Some(id) = current {
        let node = read_node(provider, state, contract, namespace, id).await.unwrap().unwrap();
        values.push(node.value.as_u64().unwrap());
        current = successor(provider, state, contract, namespace, id).await.unwrap();
    }
    values
}

#[tokio::test(flavor = "current_thread")]
async fn btree_insert_duplicate_allocates_new_node() {
    let contract = Hash::zero();
    let provider = MockProvider::default();
    let mut state = test_chain_state(contract.clone());
    let store = OpaqueBTreeStore { namespace: b"dup".to_vec() };

    let next0 = read_next_id(&provider, &mut state, &contract, &store.namespace).await.unwrap();
    assert_eq!(next0, 1);

    assert!(insert_key(
        &provider,
        &mut state,
        &contract,
        &store,
        b"k".to_vec(),
        ValueCell::from(Primitive::U64(10)),
    ).await.unwrap().is_none());

    let next1 = read_next_id(&provider, &mut state, &contract, &store.namespace).await.unwrap();
    assert_eq!(next1, 2);

    let duplicated = insert_key(
        &provider,
        &mut state,
        &contract,
        &store,
        b"k".to_vec(),
        ValueCell::from(Primitive::U64(20)),
    ).await.unwrap();
    assert!(duplicated.is_none());

    // next id advanced because a new node was allocated for the duplicate
    let next2 = read_next_id(&provider, &mut state, &contract, &store.namespace).await.unwrap();
    assert_eq!(next2, 3);

    let stored = find_key(&provider, &mut state, &contract, &store, b"k").await.unwrap();
    assert_eq!(stored.unwrap().as_u64().unwrap(), 10);
    assert_eq!(
        collect_values_in_order(&provider, &mut state, &contract, &store.namespace).await,
        vec![10, 20]
    );
}

#[tokio::test(flavor = "current_thread")]
async fn btree_delete_variants_cover_storage_cleanup() {
    let contract = Hash::zero();
    let provider = MockProvider::default();
    let mut state = test_chain_state(contract.clone());
    let store = OpaqueBTreeStore { namespace: b"delete_cases".to_vec() };

    for key in [20u64, 10, 30, 25, 35, 5, 15, 27] {
        insert_key(
            &provider,
            &mut state,
            &contract,
            &store,
            key.to_be_bytes().to_vec(),
            ValueCell::from(Primitive::U64(key)),
        ).await.unwrap();
    }

    // Leaf delete (15)
    let node15 = seek_node(&provider, &mut state, &contract, &store, &15u64.to_be_bytes(), BTreeSeekBias::Exact)
        .await.unwrap().unwrap();
    let removed = delete_key(&provider, &mut state, &contract, &store, &15u64.to_be_bytes()).await.unwrap();
    assert_eq!(removed.unwrap().as_u64().unwrap(), 15);
    assert!(read_node(&provider, &mut state, &contract, &store.namespace, node15.id).await.unwrap().is_none());

    assert_eq!(
        collect_values_in_order(&provider, &mut state, &contract, &store.namespace).await,
        vec![5, 10, 20, 25, 27, 30, 35]
    );

    // Single-child delete (25 -> 27)
    let node25 = seek_node(&provider, &mut state, &contract, &store, &25u64.to_be_bytes(), BTreeSeekBias::Exact)
        .await.unwrap().unwrap();
    delete_key(&provider, &mut state, &contract, &store, &25u64.to_be_bytes()).await.unwrap();
    assert!(read_node(&provider, &mut state, &contract, &store.namespace, node25.id).await.unwrap().is_none());
    assert_eq!(
        collect_values_in_order(&provider, &mut state, &contract, &store.namespace).await,
        vec![5, 10, 20, 27, 30, 35]
    );

    // Two-children delete (20, successor 27)
    let root_before = read_root_id(&provider, &mut state, &contract, &store.namespace).await.unwrap();
    let succ27 = seek_node(&provider, &mut state, &contract, &store, &27u64.to_be_bytes(), BTreeSeekBias::Exact)
        .await.unwrap().unwrap();
    delete_key(&provider, &mut state, &contract, &store, &20u64.to_be_bytes()).await.unwrap();
    let root_after = read_root_id(&provider, &mut state, &contract, &store.namespace).await.unwrap();
    assert_eq!(root_after, root_before);
    assert!(read_node(&provider, &mut state, &contract, &store.namespace, succ27.id).await.unwrap().is_none());
    assert_eq!(
        collect_values_in_order(&provider, &mut state, &contract, &store.namespace).await,
        vec![5, 10, 27, 30, 35]
    );

    for key in [5u64, 10, 27, 30, 35] {
        delete_key(&provider, &mut state, &contract, &store, &key.to_be_bytes()).await.unwrap();
    }
    assert_eq!(read_root_id(&provider, &mut state, &contract, &store.namespace).await.unwrap(), 0);
    assert!(collect_values_in_order(&provider, &mut state, &contract, &store.namespace).await.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn btree_cursor_cache_refresh_tracks_state() {
    let contract = Hash::zero();
    let provider = MockProvider::default();
    let mut state = test_chain_state(contract.clone());
    let store = OpaqueBTreeStore { namespace: b"cursor_cache".to_vec() };

    for key in [10u64, 20, 30] {
        insert_key(
            &provider,
            &mut state,
            &contract,
            &store,
            key.to_be_bytes().to_vec(),
            ValueCell::from(Primitive::U64(key)),
        ).await.unwrap();
    }

    let n20 = seek_node(&provider, &mut state, &contract, &store, &20u64.to_be_bytes(), BTreeSeekBias::Exact)
        .await.unwrap().unwrap();
    let mut cursor = OpaqueBTreeCursor {
        contract: contract.clone(),
        namespace: store.namespace.clone(),
        current_node: Some(n20.id),
        cached_key: None,
        cached_value: None,
    };

    refresh_cursor_cache(&mut cursor, &provider, &mut state).await.unwrap();
    assert_eq!(cursor.cached_key.as_deref(), Some(&20u64.to_be_bytes()[..]));
    assert_eq!(cursor.cached_value.as_ref().unwrap().as_u64().unwrap(), 20);

    let next = successor(&provider, &mut state, &contract, &store.namespace, n20.id).await.unwrap().unwrap();
    cursor.current_node = Some(next);
    refresh_cursor_cache(&mut cursor, &provider, &mut state).await.unwrap();
    assert_eq!(cursor.cached_value.as_ref().unwrap().as_u64().unwrap(), 30);

    delete_key(&provider, &mut state, &contract, &store, &30u64.to_be_bytes()).await.unwrap();
    refresh_cursor_cache(&mut cursor, &provider, &mut state).await.unwrap();
    assert!(cursor.current_node.is_none());
    assert!(cursor.cached_key.is_none() && cursor.cached_value.is_none());

    cursor.current_node = None;
    refresh_cursor_cache(&mut cursor, &provider, &mut state).await.unwrap();
    assert!(cursor.cached_key.is_none() && cursor.cached_value.is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn btree_cache_prefetch_reads_values() {
    let contract = Hash::zero();
    let mut provider = MockProvider::default();
    let mut state = test_chain_state(contract.clone());
    let namespace = b"prefetch".to_vec();
    let root_key = root_storage_key(&namespace);

    provider.data.insert(
        (contract.clone(), root_key.clone()),
        (5, Some(ValueCell::from(Primitive::U64(77)))),
    );

    let root = read_root_id(&provider, &mut state, &contract, &namespace).await.unwrap();
    assert_eq!(root, 77);

    let root_again = read_root_id(&provider, &mut state, &contract, &namespace).await.unwrap();
    assert_eq!(root_again, 77);
}

#[tokio::test(flavor = "current_thread")]
async fn btree_seek_empty_and_bounds() {
    let contract = Hash::zero();
    let provider = MockProvider::default();
    let mut state = test_chain_state(contract.clone());
    let store = OpaqueBTreeStore { namespace: b"bounds".to_vec() };

    for bias in [
        BTreeSeekBias::Exact,
        BTreeSeekBias::Greater,
        BTreeSeekBias::GreaterOrEqual,
        BTreeSeekBias::Less,
        BTreeSeekBias::LessOrEqual,
    ] {
        assert!(seek_node(&provider, &mut state, &contract, &store, &10u64.to_be_bytes(), bias).await.unwrap().is_none());
    }

    for key in [10u64, 20, 30] {
        insert_key(
            &provider,
            &mut state,
            &contract,
            &store,
            key.to_be_bytes().to_vec(),
            ValueCell::from(Primitive::U64(key)),
        ).await.unwrap();
    }

    assert_eq!(
        seek_node(&provider, &mut state, &contract, &store, &5u64.to_be_bytes(), BTreeSeekBias::GreaterOrEqual)
            .await.unwrap().unwrap().value.as_u64().unwrap(),
        10
    );
    assert!(seek_node(&provider, &mut state, &contract, &store, &5u64.to_be_bytes(), BTreeSeekBias::LessOrEqual).await.unwrap().is_none());

    assert_eq!(
        seek_node(&provider, &mut state, &contract, &store, &40u64.to_be_bytes(), BTreeSeekBias::LessOrEqual)
            .await.unwrap().unwrap().value.as_u64().unwrap(),
        30
    );
    assert!(seek_node(&provider, &mut state, &contract, &store, &40u64.to_be_bytes(), BTreeSeekBias::GreaterOrEqual).await.unwrap().is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn btree_namespace_isolation() {
    let contract = Hash::zero();
    let provider = MockProvider::default();
    let mut state = test_chain_state(contract.clone());
    let store_a = OpaqueBTreeStore { namespace: b"A".to_vec() };
    let store_b = OpaqueBTreeStore { namespace: b"B".to_vec() };

    insert_key(
        &provider,
        &mut state,
        &contract,
        &store_a,
        b"x".to_vec(),
        ValueCell::from(Primitive::U64(1)),
    ).await.unwrap();

    let val_a = find_key(&provider, &mut state, &contract, &store_a, b"x").await.unwrap();
    assert_eq!(val_a.unwrap().as_u64().unwrap(), 1);
    assert!(find_key(&provider, &mut state, &contract, &store_b, b"x").await.unwrap().is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn btree_node_serialization_roundtrip_matches_original() {
    let node = Node {
        id: 42,
        key: b"abc".to_vec(),
        value: ValueCell::from(Primitive::U64(99)),
        parent: Some(7),
        left: Some(8),
        right: None,
    };

    let roundtrip = Node::from_value(42, &node.to_value()).unwrap();
    assert_eq!(roundtrip.id, 42);
    assert_eq!(roundtrip.key, b"abc".to_vec());
    assert_eq!(roundtrip.value.as_u64().unwrap(), 99);
    assert_eq!(roundtrip.parent, Some(7));
    assert_eq!(roundtrip.left, Some(8));
    assert_eq!(roundtrip.right, None);
}

#[tokio::test(flavor = "current_thread")]
async fn btree_key_value_constraints_reject_invalid_inputs() {
    assert!(read_key_bytes(ValueCell::Bytes(vec![])).is_err());

    let huge_key = vec![0u8; MAX_KEY_SIZE + 1];
    assert!(read_key_bytes(ValueCell::Bytes(huge_key)).is_err());

    let huge_value = ValueCell::Bytes(vec![0u8; MAX_VALUE_SIZE + 1]);
    assert!(ensure_value_constraints(&huge_value).is_err());

    assert!(ensure_value_constraints(&ValueCell::Bytes(vec![1, 2, 3])).is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn btree_allocate_node_id_monotonic_per_namespace() {
    let contract = Hash::zero();
    let provider = MockProvider::default();
    let mut state = test_chain_state(contract.clone());
    let namespace = b"id_alloc".to_vec();

    let first = allocate_node_id(&provider, &mut state, &contract, &namespace).await.unwrap();
    let second = allocate_node_id(&provider, &mut state, &contract, &namespace).await.unwrap();
    let third = allocate_node_id(&provider, &mut state, &contract, &namespace).await.unwrap();

    assert_eq!((first, second, third), (1, 2, 3));
}

