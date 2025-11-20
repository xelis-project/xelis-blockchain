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

#[test]
fn btree_header_matches_full_node_layout() {
    let node = Node::new(1, b"k".to_vec(), ValueCell::from(Primitive::U64(7)), Some(2));
    let bytes = node.to_bytes();
    let value = ValueCell::Bytes(bytes);
    let hdr = super::node_header_from_value(1, &value).expect("header decode");
    let full = Node::from_value(1, &value).expect("full decode");
    assert_eq!(hdr.id, full.id);
    assert_eq!(hdr.key, full.key);
    assert_eq!(hdr.parent, full.parent);
    assert_eq!(hdr.left, full.left);
    assert_eq!(hdr.right, full.right);
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
        cached_value: Some(start_node.value.clone()),
        ascending: true,
    };

    let mut observed = Vec::new();
    while let Some(current_id) = cursor.current_node {
        refresh_cursor_cache(&mut cursor, &provider, &mut state).await.unwrap();
        let node = read_node(&provider, &mut state, &contract, &store.namespace, current_id).await.unwrap().unwrap();
        let key = u64::from_be_bytes(node.key[..8].try_into().unwrap());
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
        cached_value: Some(first.value.clone()),
        ascending: true,
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

    // Treap rotations may choose a different node as the root compared to the original unbalanced
    // implementation, but the deleted key must be gone and the remaining keys must stay ordered.
    let root_id = read_root_id(&provider, &mut state, &contract, &store.namespace).await.unwrap();
    assert_ne!(root_id, 0);
    let root = read_node(&provider, &mut state, &contract, &store.namespace, root_id).await.unwrap().unwrap();
    assert_ne!(root.key, 40u64.to_be_bytes().to_vec());

    // Remaining nodes still searchable
    assert_eq!(
        find_key(&provider, &mut state, &contract, &store, &50u64.to_be_bytes()).await.unwrap()
            .unwrap()
            .as_u64()
            .unwrap(),
        500
    );
    assert_eq!(
        collect_values_in_order(&provider, &mut state, &contract, &store.namespace).await,
        vec![200, 500, 600]
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
        cached_value: Some(cursor.value.clone()),
        ascending: true,
    };

    // Key/value come from cached data
    assert_eq!(cursor.cached_value.as_ref().unwrap().as_u64().unwrap(), 20);

    cursor.cached_value = None;
    refresh_cursor_cache(&mut cursor, &provider, &mut state).await.unwrap();
    assert_eq!(cursor.cached_value.as_ref().unwrap().as_u64().unwrap(), 20);

    cursor.current_node = successor(&provider, &mut state, &contract, &store.namespace, cursor.current_node.unwrap()).await.unwrap();
    refresh_cursor_cache(&mut cursor, &provider, &mut state).await.unwrap();
    assert_eq!(cursor.cached_value.as_ref().unwrap().as_u64().unwrap(), 30);

    assert!(cursor.cached_value.is_some());

    cursor.current_node = successor(&provider, &mut state, &contract, &store.namespace, cursor.current_node.unwrap()).await.unwrap();
    refresh_cursor_cache(&mut cursor, &provider, &mut state).await.unwrap();
    assert!(cursor.cached_value.is_none());
    assert!(cursor.current_node.is_none());
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
        cached_value: Some(cursor_node.value.clone()),
        ascending: true,
    };

    let mut outputs = Vec::new();
    loop {
        let Some(current_id) = cursor.current_node else { break; };
        let node = read_node(&provider, &mut state, &contract, &store.namespace, current_id).await.unwrap().unwrap();
        let key_bytes = node.key;
        outputs.push(u64::from_be_bytes(key_bytes[..8].try_into().unwrap()));
        delete_key(&provider, &mut state, &contract, &store, &key_bytes).await.unwrap();

        refresh_cursor_cache(&mut cursor, &provider, &mut state).await.unwrap();
        if cursor.current_node.is_none() {
            break;
        }

        cursor.current_node = successor(&provider, &mut state, &contract, &store.namespace, current_id).await.unwrap();
        refresh_cursor_cache(&mut cursor, &provider, &mut state).await.unwrap();
    }

    assert_eq!(outputs, vec![10]);
    assert!(cursor.current_node.is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn btree_cursor_selective_delete_during_scan() {
    let contract = Hash::zero();
    let provider = MockProvider::default();
    let mut state = test_chain_state(contract.clone());
    let store = OpaqueBTreeStore { namespace: b"scan_delete_subset".to_vec() };

    let mut rng = StdRng::seed_from_u64(0xD3_1E7E);
    let mut expected = Vec::new();

    // Insert 100 keys with range 1..=20 (lots of duplicates)
    // Values are unique (0..100) to verify identity
    for i in 0..100 {
        let key = rng.gen_range(1..=20u64);
        let value = i as u64;
        insert_key(
            &provider,
            &mut state,
            &contract,
            &store,
            key.to_be_bytes().to_vec(),
            ValueCell::from(Primitive::U64(value)),
        ).await.unwrap();
        expected.push((key, value));
    }

    // Expected order: Key ascending, then insertion order (ID ascending) for duplicates.
    expected.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

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
        cached_value: Some(cursor_node.value.clone()),
        ascending: true,
    };

    let mut kept_values = Vec::new();

    for (index, (exp_key, exp_val)) in expected.iter().enumerate() {
        refresh_cursor_cache(&mut cursor, &provider, &mut state).await.unwrap();
        let current_id = cursor.current_node.expect("Cursor should not end early");

        let node = read_node(&provider, &mut state, &contract, &store.namespace, current_id).await.unwrap().unwrap();
        let key_bytes = node.key;
        let key = u64::from_be_bytes(key_bytes[..8].try_into().unwrap());
        let value = cursor.cached_value.as_ref().unwrap().as_u64().unwrap();

        // Verify we are looking at the expected item
        assert_eq!((key, value), (*exp_key, *exp_val), "Cursor position mismatch at index {}", index);

        // Delete every 3rd key (index 0, 3, 6...)
        if index % 3 == 0 {
            // Use delete_at_cursor which safely deletes the current node by ID
            let mut ctx = TreeContext::new(&provider, &mut state, &contract, &store.namespace);
            let removed = super::delete_at_cursor(&mut cursor, &mut ctx).await.unwrap();
            let removed_value = removed.expect("value exists").as_u64().unwrap();
            
            assert_eq!(removed_value, *exp_val, "Deleted value mismatch for key {}", key);
        } else {
            kept_values.push(*exp_val);
            // Manually advance the cursor
            let next_id = successor(&provider, &mut state, &contract, &store.namespace, current_id).await.unwrap();
            cursor.current_node = next_id;
            cursor.cached_value = None; // Force refresh on next iteration
        }
    }
    
    // Verify cursor is exhausted
    refresh_cursor_cache(&mut cursor, &provider, &mut state).await.unwrap();
    assert!(cursor.current_node.is_none());

    // Verify remaining items in storage match what we skipped
    let remaining_in_storage = collect_values_in_order(&provider, &mut state, &contract, &store.namespace).await;
    assert_eq!(remaining_in_storage, kept_values);
}

#[tokio::test(flavor = "current_thread")]
async fn btree_cursor_consecutive_deletes() {
    let contract = Hash::zero();
    let provider = MockProvider::default();
    let mut state = test_chain_state(contract.clone());
    let store = OpaqueBTreeStore { namespace: b"cursor_consecutive_delete".to_vec() };

    for key in 1u64..=10 {
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
        cached_value: Some(cursor_node.value.clone()),
        ascending: true,
    };

    for expected in 1u64..=3 {
        refresh_cursor_cache(&mut cursor, &provider, &mut state).await.unwrap();
        let current_id = cursor.current_node.expect("cursor should still point to a node");
        let node = read_node(&provider, &mut state, &contract, &store.namespace, current_id).await.unwrap().unwrap();
        let key = u64::from_be_bytes(node.key[..8].try_into().unwrap());
        assert_eq!(key, expected);

        let mut ctx = TreeContext::new(&provider, &mut state, &contract, &store.namespace);
        let removed = super::delete_at_cursor(&mut cursor, &mut ctx).await.unwrap();
        assert_eq!(removed.unwrap().as_u64().unwrap(), expected);
    }

    refresh_cursor_cache(&mut cursor, &provider, &mut state).await.unwrap();
    assert_eq!(
        cursor.cached_value.as_ref().unwrap().as_u64().unwrap(),
        4,
        "cursor should advance to the first non-deleted node",
    );

    let remaining = collect_values_in_order(&provider, &mut state, &contract, &store.namespace).await;
    let expected_remaining: Vec<u64> = (4u64..=10).collect();
    assert_eq!(remaining, expected_remaining);
}

#[tokio::test(flavor = "current_thread")]
async fn btree_cursor_exhausts_tree() {
    let contract = Hash::zero();
    let provider = MockProvider::default();
    let mut state = test_chain_state(contract.clone());
    let store = OpaqueBTreeStore { namespace: b"cursor_exhaust_tree".to_vec() };

    for key in 1u64..=5 {
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
        cached_value: Some(cursor_node.value.clone()),
        ascending: true,
    };

    let mut removed_values = Vec::new();
    loop {
        refresh_cursor_cache(&mut cursor, &provider, &mut state).await.unwrap();
        let Some(_) = cursor.current_node else {
            break;
        };
        let mut ctx = TreeContext::new(&provider, &mut state, &contract, &store.namespace);
        let removed = super::delete_at_cursor(&mut cursor, &mut ctx).await.unwrap();
        removed_values.push(removed.unwrap().as_u64().unwrap());
    }

    assert_eq!(removed_values, vec![1, 2, 3, 4, 5]);
    assert!(cursor.current_node.is_none());
    assert!(cursor.cached_value.is_none());
    assert_eq!(
        read_root_id(&provider, &mut state, &contract, &store.namespace).await.unwrap(),
        0,
        "root pointer must be cleared once the tree is empty",
    );
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
    let node20 = seek_node(&provider, &mut state, &contract, &store, &20u64.to_be_bytes(), BTreeSeekBias::Exact)
        .await.unwrap().unwrap();
    let succ27 = seek_node(&provider, &mut state, &contract, &store, &27u64.to_be_bytes(), BTreeSeekBias::Exact)
        .await.unwrap().unwrap();
    delete_key(&provider, &mut state, &contract, &store, &20u64.to_be_bytes()).await.unwrap();
    assert!(read_node(&provider, &mut state, &contract, &store.namespace, node20.id).await.unwrap().is_none());
    assert!(read_node(&provider, &mut state, &contract, &store.namespace, succ27.id).await.unwrap().is_some());
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
        cached_value: None,
        ascending: true,
    };

    refresh_cursor_cache(&mut cursor, &provider, &mut state).await.unwrap();
    let current = cursor.current_node.unwrap();
    let node = read_node(&provider, &mut state, &contract, &store.namespace, current).await.unwrap().unwrap();
    assert_eq!(u64::from_be_bytes(node.key[..8].try_into().unwrap()), 20);
    assert_eq!(cursor.cached_value.as_ref().unwrap().as_u64().unwrap(), 20);

    let next = successor(&provider, &mut state, &contract, &store.namespace, n20.id).await.unwrap().unwrap();
    cursor.current_node = Some(next);
    refresh_cursor_cache(&mut cursor, &provider, &mut state).await.unwrap();
    assert_eq!(cursor.cached_value.as_ref().unwrap().as_u64().unwrap(), 30);

    delete_key(&provider, &mut state, &contract, &store, &30u64.to_be_bytes()).await.unwrap();
    refresh_cursor_cache(&mut cursor, &provider, &mut state).await.unwrap();
    assert!(cursor.current_node.is_none());
    assert!(cursor.cached_value.is_none());

    cursor.current_node = None;
    refresh_cursor_cache(&mut cursor, &provider, &mut state).await.unwrap();
    assert!(cursor.cached_value.is_none());
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

#[tokio::test(flavor = "current_thread")]
async fn btree_storage_usage_records_reads() {
    let contract = Hash::zero();
    let provider = MockProvider::default();
    let mut state = test_chain_state(contract.clone());
    let namespace = b"usage_read".to_vec();

    let mut ctx = TreeContext::new(&provider, &mut state, &contract, &namespace);
    let result = super::read_node(&mut ctx, 1).await.unwrap();
    assert!(result.is_none());

    let usage = ctx.finish();
    assert_eq!(usage.read_bytes, 26, "expected storage read bytes");
    assert_eq!(usage.written_bytes, 0, "read path should not record written bytes");
}

#[tokio::test(flavor = "current_thread")]
async fn btree_storage_usage_records_writes() {
    let contract = Hash::zero();
    let provider = MockProvider::default();
    let mut state = test_chain_state(contract.clone());
    let namespace = b"usage_write".to_vec();

    let mut ctx = TreeContext::new(&provider, &mut state, &contract, &namespace);
    super::write_root_id(&mut ctx, 42).await.unwrap();

    let usage = ctx.finish();
    assert_eq!(usage.read_bytes, 0, "writing the root should not read storage");
    assert_eq!(usage.written_bytes, 35, "expected storage written bytes");
}

#[tokio::test(flavor = "current_thread")]
async fn btree_storage_usage_single_insert_reports_activity() {
    let contract = Hash::zero();
    let provider = MockProvider::default();
    let mut state = test_chain_state(contract.clone());
    let store = OpaqueBTreeStore { namespace: b"insert_usage".to_vec() };

    let mut ctx = TreeContext::new(&provider, &mut state, &contract, &store.namespace);
    super::insert_key(&mut ctx, b"k".to_vec(), ValueCell::from(Primitive::U64(1))).await.unwrap();
    let usage = ctx.finish();

    assert_eq!(usage.read_bytes, 52, "insert should read bytes");
    assert_eq!(usage.written_bytes, 141, "insert should write bytes");
}

#[tokio::test(flavor = "current_thread")]
async fn btree_storage_usage_delete_reports_activity() {
    let contract = Hash::zero();
    let provider = MockProvider::default();
    let mut state = test_chain_state(contract.clone());
    let store = OpaqueBTreeStore { namespace: b"delete_usage".to_vec() };

    insert_key(
        &provider,
        &mut state,
        &contract,
        &store,
        b"k".to_vec(),
        ValueCell::from(Primitive::U64(7)),
    ).await.unwrap();

    let mut ctx = TreeContext::new(&provider, &mut state, &contract, &store.namespace);
    let removed = super::delete_key(&mut ctx, b"k").await.unwrap();
    assert!(removed.is_some(), "expected the key to be removed");
    let usage = ctx.finish();

    assert_eq!(usage.written_bytes, 64, "delete should write bytes");
    assert_eq!(usage.read_bytes, 0, "reads should be cached");
}

// --- helpers specific to new tests ---

async fn predecessor(
    provider: &MockProvider,
    state: &mut ChainState<'_>,
    contract: &Hash,
    namespace: &[u8],
    node_id: u64,
) -> Result<Option<u64>, EnvironmentError> {
    let mut ctx = TreeContext::new(provider, state, contract, namespace);
    super::predecessor(&mut ctx, node_id).await
}

async fn btree_assert_treap_invariants(
    provider: &MockProvider,
    state: &mut ChainState<'_>,
    contract: &Hash,
    namespace: &[u8],
) {
    use std::cmp::Ordering;

    let root_id = read_root_id(provider, state, contract, namespace).await.unwrap();
    if root_id == 0 { return; }

    // Root must have no parent
    let root = read_node(provider, state, contract, namespace, root_id).await.unwrap().unwrap();
    assert!(root.parent.is_none());

    // DFS over the tree verifying BST and heap properties and parent pointers
    let mut stack = vec![root_id];
    while let Some(id) = stack.pop() {
        let n = read_node(provider, state, contract, namespace, id).await.unwrap().unwrap();
        let p = super::priority_for_pair(&n.key, n.id);

        if let Some(l) = n.left {
            let ln = read_node(provider, state, contract, namespace, l).await.unwrap().unwrap();
            assert!(matches!(super::cmp_pair(&ln.key, ln.id, &n.key, n.id), Ordering::Less));
            assert_eq!(ln.parent, Some(n.id));
            assert!(p >= super::priority_for_pair(&ln.key, ln.id));
            stack.push(l);
        }
        if let Some(r) = n.right {
            let rn = read_node(provider, state, contract, namespace, r).await.unwrap().unwrap();
            assert!(matches!(super::cmp_pair(&rn.key, rn.id, &n.key, n.id), Ordering::Greater));
            assert_eq!(rn.parent, Some(n.id));
            assert!(p >= super::priority_for_pair(&rn.key, rn.id));
            stack.push(r);
        }
    }
}

// --- tests ---

#[tokio::test(flavor = "current_thread")]
async fn btree_treap_invariants_after_random_inserts_and_deletes() {
    use rand::{rngs::StdRng, Rng, SeedableRng};

    let contract = Hash::zero();
    let provider = MockProvider::default();
    let mut state = test_chain_state(contract.clone());
    let store = OpaqueBTreeStore { namespace: b"invariants".to_vec() };

    // Insert unique random keys (value == key for easy cross-checks).
    let mut rng = StdRng::seed_from_u64(0xC0FF_EE);
    let mut keys = IndexSet::new();
    while keys.len() < 128 {
        keys.insert(rng.gen::<u64>());
    }
    for &k in &keys {
        insert_key(
            &provider, &mut state, &contract, &store,
            k.to_be_bytes().to_vec(), ValueCell::from(Primitive::U64(k)),
        ).await.unwrap();
    }
    btree_assert_treap_invariants(&provider, &mut state, &contract, &store.namespace).await;

    // Delete every 3rd key; invariants must still hold each step.
    for (i, &k) in keys.iter().enumerate() {
        if i % 3 == 0 {
            delete_key(&provider, &mut state, &contract, &store, &k.to_be_bytes()).await.unwrap();
            btree_assert_treap_invariants(&provider, &mut state, &contract, &store.namespace).await;
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn btree_treap_rotate_left_at_root_updates_links() {
    let contract = Hash::zero();
    let provider = MockProvider::default();
    let mut state = test_chain_state(contract.clone());
    let store = OpaqueBTreeStore { namespace: b"rot_left_root".to_vec() };

    // First insert creates root (id = 1)
    let k1 = 1_000_000_000u64;
    insert_key(
        &provider, &mut state, &contract, &store,
        k1.to_be_bytes().to_vec(), ValueCell::from(Primitive::U64(1)),
    ).await.unwrap();
    let p1 = super::priority_for_pair(&k1.to_be_bytes(), 1);

    // Choose k2 > k1 with priority(k2, id=2) > p1 to force a left rotation at root.
    let mut k2 = k1 + 1;
    while super::priority_for_pair(&k2.to_be_bytes(), 2) <= p1 {
        k2 += 1;
    }
    insert_key(
        &provider, &mut state, &contract, &store,
        k2.to_be_bytes().to_vec(), ValueCell::from(Primitive::U64(2)),
    ).await.unwrap();

    let root_id = read_root_id(&provider, &mut state, &contract, &store.namespace).await.unwrap();
    let root = read_node(&provider, &mut state, &contract, &store.namespace, root_id).await.unwrap().unwrap();
    assert_eq!(root.key, k2.to_be_bytes().to_vec());
    assert!(root.parent.is_none());

    // Left child should be the former root (k1) and its parent should be the new root (k2).
    let left_id = root.left.expect("left child must exist after rotate_left");
    let left = read_node(&provider, &mut state, &contract, &store.namespace, left_id).await.unwrap().unwrap();
    assert_eq!(left.key, k1.to_be_bytes().to_vec());
    assert_eq!(left.parent, Some(root_id));
    assert!(left.right.is_none()); // No beta subtree in this 2-node scenario

    btree_assert_treap_invariants(&provider, &mut state, &contract, &store.namespace).await;
}

#[tokio::test(flavor = "current_thread")]
async fn btree_treap_rotate_right_under_parent_updates_links() {
    // Force a right rotation on the left child of the root and ensure parent links are updated.
    let contract = Hash::zero();
    let provider = MockProvider::default();
    let mut state = test_chain_state(contract.clone());
    let store = OpaqueBTreeStore { namespace: b"rot_right_child".to_vec() };

    let k1 = 1_000_000_000u64; // root
    insert_key(&provider, &mut state, &contract, &store, k1.to_be_bytes().to_vec(), ValueCell::from(Primitive::U64(1))).await.unwrap();
    let p1 = super::priority_for_pair(&k1.to_be_bytes(), 1);

    // Choose k2 < k1 with p2 < p1 so it stays as left child (no rotation to root).
    let mut k2 = k1 - 1;
    while super::priority_for_pair(&k2.to_be_bytes(), 2) >= p1 {
        k2 -= 1;
    }
    insert_key(&provider, &mut state, &contract, &store, k2.to_be_bytes().to_vec(), ValueCell::from(Primitive::U64(2))).await.unwrap();
    let p2 = super::priority_for_pair(&k2.to_be_bytes(), 2);

    // Choose k3 < k2 with p2 < p3 <= p1 to rotate above k2 but not above k1.
    let mut k3 = k2 - 1;
    loop {
        let p3 = super::priority_for_pair(&k3.to_be_bytes(), 3);
        if p3 > p2 && p3 <= p1 { break; }
        k3 -= 1;
    }
    insert_key(&provider, &mut state, &contract, &store, k3.to_be_bytes().to_vec(), ValueCell::from(Primitive::U64(3))).await.unwrap();

    let root_id = read_root_id(&provider, &mut state, &contract, &store.namespace).await.unwrap();
    let root = read_node(&provider, &mut state, &contract, &store.namespace, root_id).await.unwrap().unwrap();
    assert_eq!(root.key, k1.to_be_bytes().to_vec(), "root should remain k1");

    let left_id = root.left.expect("root must have a left child after rotation");
    let left = read_node(&provider, &mut state, &contract, &store.namespace, left_id).await.unwrap().unwrap();
    assert_eq!(left.key, k3.to_be_bytes().to_vec(), "left child should be k3 after rotate_right at k2");
    assert_eq!(left.parent, Some(root_id));

    let k3_right = left.right.expect("k3.right should be k2");
    let n2 = read_node(&provider, &mut state, &contract, &store.namespace, k3_right).await.unwrap().unwrap();
    assert_eq!(n2.key, k2.to_be_bytes().to_vec());
    assert_eq!(n2.parent, Some(left_id));

    btree_assert_treap_invariants(&provider, &mut state, &contract, &store.namespace).await;
}

#[tokio::test(flavor = "current_thread")]
async fn btree_treap_seek_with_duplicates_bias_matrix() {
    let contract = Hash::zero();
    let provider = MockProvider::default();
    let mut state = test_chain_state(contract.clone());
    let store = OpaqueBTreeStore { namespace: b"dup_bias".to_vec() };

    // Keys: 6, 7 (x3), 8
    insert_key(&provider, &mut state, &contract, &store, 6u64.to_be_bytes().to_vec(), ValueCell::from(Primitive::U64(6))).await.unwrap();
    for v in [1u64, 2, 3] {
        insert_key(&provider, &mut state, &contract, &store, 7u64.to_be_bytes().to_vec(), ValueCell::from(Primitive::U64(v))).await.unwrap();
    }
    insert_key(&provider, &mut state, &contract, &store, 8u64.to_be_bytes().to_vec(), ValueCell::from(Primitive::U64(8))).await.unwrap();

    let exact = seek_node(&provider, &mut state, &contract, &store, &7u64.to_be_bytes(), BTreeSeekBias::Exact).await.unwrap().unwrap();
    assert_eq!(exact.value.as_u64().unwrap(), 1, "Exact must return first duplicate");

    let ge = seek_node(&provider, &mut state, &contract, &store, &7u64.to_be_bytes(), BTreeSeekBias::GreaterOrEqual).await.unwrap().unwrap();
    assert_eq!(ge.value.as_u64().unwrap(), 1, "GE must return first duplicate");

    let gt = seek_node(&provider, &mut state, &contract, &store, &7u64.to_be_bytes(), BTreeSeekBias::Greater).await.unwrap().unwrap();
    assert_eq!(gt.value.as_u64().unwrap(), 8, "G must skip entire duplicate bucket");

    let le = seek_node(&provider, &mut state, &contract, &store, &7u64.to_be_bytes(), BTreeSeekBias::LessOrEqual).await.unwrap().unwrap();
    assert_eq!(le.value.as_u64().unwrap(), 3, "LE must return last duplicate");

    let lt = seek_node(&provider, &mut state, &contract, &store, &7u64.to_be_bytes(), BTreeSeekBias::Less).await.unwrap().unwrap();
    assert_eq!(lt.value.as_u64().unwrap(), 6, "L must return previous distinct key");
}

#[tokio::test(flavor = "current_thread")]
async fn btree_treap_predecessor_through_duplicate_bucket() {
    let contract = Hash::zero();
    let provider = MockProvider::default();
    let mut state = test_chain_state(contract.clone());
    let store = OpaqueBTreeStore { namespace: b"dup_pred".to_vec() };

    insert_key(&provider, &mut state, &contract, &store, 8u64.to_be_bytes().to_vec(), ValueCell::from(Primitive::U64(8))).await.unwrap();
    for v in [10u64, 20, 30] {
        insert_key(&provider, &mut state, &contract, &store, 9u64.to_be_bytes().to_vec(), ValueCell::from(Primitive::U64(v))).await.unwrap();
    }

    // Get the middle duplicate (value=20)
    let first = seek_node(&provider, &mut state, &contract, &store, &9u64.to_be_bytes(), BTreeSeekBias::Exact).await.unwrap().unwrap();
    let second_id = successor(&provider, &mut state, &contract, &store.namespace, first.id).await.unwrap().unwrap();

    // predecessor of middle -> first duplicate
    let pred_mid = predecessor(&provider, &mut state, &contract, &store.namespace, second_id).await.unwrap().unwrap();
    let pred_mid_node = read_node(&provider, &mut state, &contract, &store.namespace, pred_mid).await.unwrap().unwrap();
    assert_eq!(pred_mid_node.value.as_u64().unwrap(), 10);

    // predecessor of first duplicate -> previous distinct key (8)
    let pred_first = predecessor(&provider, &mut state, &contract, &store.namespace, first.id).await.unwrap().unwrap();
    let pred_first_node = read_node(&provider, &mut state, &contract, &store.namespace, pred_first).await.unwrap().unwrap();
    assert_eq!(pred_first_node.value.as_u64().unwrap(), 8);

    // predecessor of the smallest key -> None
    let root_id = read_root_id(&provider, &mut state, &contract, &store.namespace).await.unwrap();
    let min = find_min_node(&provider, &mut state, &contract, &store.namespace, root_id).await.unwrap();
    assert!(predecessor(&provider, &mut state, &contract, &store.namespace, min.id).await.unwrap().is_none());
}