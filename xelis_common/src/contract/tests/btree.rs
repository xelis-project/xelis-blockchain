use crate::{block::BlockVersion, contract::vm::ExitValue};
use super::*;

/// Test basic BTree insert and get operations
#[tokio::test]
async fn test_btree_insert_and_get() {
    let code = r#"
        entry insert_value(key: bytes, value: bytes) {
            let store = BTreeStore::new(key);
            store.insert(key, value);
            return 0
        }

        entry get_value(key: bytes) -> bytes {
            let store = BTreeStore::new(key);
            let value = store.get(key).unwrap();
            return value
        }
    "#;

    let mut chain_state = MockChainState::with(BlockVersion::V6);
    let contract_hash = deploy_contract(&mut chain_state, code, ContractVersion::V1)
        .await
        .expect("deploy contract")
        .0;

    // Insert a value
    let result = invoke_contract(
        &mut chain_state,
        &contract_hash,
        InvokeContract::Entry(0),
        vec![
            ValueCell::Bytes("test_key".as_bytes().to_vec()),
            ValueCell::Bytes("test_value".as_bytes().to_vec()),
        ],
    )
    .await
    .expect("insert value");

    assert!(result.is_success(), "insert should succeed: {:?}", result);

    let storage = &chain_state.contract_caches.get(&contract_hash)
        .expect("contract cache")
        .storage;
    assert!(!storage.is_empty(), "storage should have entries after insert");

    // Get the value back
    let result = invoke_contract(
        &mut chain_state,
        &contract_hash,
        InvokeContract::Entry(1),
        vec![ValueCell::Bytes("test_key".as_bytes().to_vec())],
    )
    .await
    .expect("get value");

    assert!(result.is_success(), "get should succeed: {:?}", result);

    let ExitValue::Payload(ValueCell::Bytes(payload)) = result.exit_value else {
        panic!("invalid exit value");
    };

    assert!(payload == b"test_value".to_vec());
}

/// Test BTree delete operations
#[tokio::test]
async fn test_btree_delete() {
    let code = r#"
        entry insert_value(key: bytes, value: bytes) {
            let store = BTreeStore::new(key);
            store.insert(key, value);
            return 0
        }

        entry get_value(key: bytes) -> bytes {
            let store = BTreeStore::new(key);
            return store.get(key).expect("key should exist")
        }

        entry delete_value(key: bytes) -> bool {
            let store = BTreeStore::new(key);
            return store.delete(key)
        }
    "#;

    let mut chain_state = MockChainState::new();
    let contract_hash = deploy_contract(&mut chain_state, code, ContractVersion::V1)
        .await
        .expect("deploy contract")
        .0;

    // Insert a value
    invoke_contract(
        &mut chain_state,
        &contract_hash,
        InvokeContract::Entry(0),
        vec![
            ValueCell::Bytes("key1".as_bytes().to_vec()),
            ValueCell::Bytes("value1".as_bytes().to_vec()),
        ],
    )
    .await
    .expect("insert");

    // Try to get the deleted value (should be present)
    let result = invoke_contract(
        &mut chain_state,
        &contract_hash,
        InvokeContract::Entry(1),
        vec![ValueCell::Bytes("key1".as_bytes().to_vec())],
    )
    .await
    .expect("get present");

    assert!(result.is_success(), "get deleted should succeed: {:?}", result);

    // Delete the value
    let result = invoke_contract(
        &mut chain_state,
        &contract_hash,
        InvokeContract::Entry(2),
        vec![ValueCell::Bytes("key1".as_bytes().to_vec())],
    )
    .await
    .expect("delete");

    assert!(result.is_success(), "delete should succeed: {:?}", result);

    // Try to get the deleted value (should be empty)
    let result = invoke_contract(
        &mut chain_state,
        &contract_hash,
        InvokeContract::Entry(1),
        vec![ValueCell::Bytes("key1".as_bytes().to_vec())],
    )
    .await
    .expect("get deleted");

    assert!(!result.is_success(), "get deleted should fail: {:?}", result);
}

/// Test BTree multiple values with same key (duplicate key handling)
#[tokio::test]
async fn test_btree_duplicate_keys() {
    let code = r#"
        entry insert_multiple(key: bytes, val1: bytes, val2: bytes, val3: bytes) {
            let store = BTreeStore::new(key);
            store.insert(key, val1);
            store.insert(key, val2);
            store.insert(key, val3);
            return 0
        }

        entry get_first(key: bytes) -> optional<bytes> {
            let store = BTreeStore::new(key);
            return store.get(key)
        }

        entry delete_and_get_next(key: bytes) -> optional<bytes> {
            let store = BTreeStore::new(key);
            store.delete(key);
            return store.get(key)
        }
    "#;

    let mut chain_state = MockChainState::new();
    let contract_hash = deploy_contract(&mut chain_state, code, ContractVersion::V1)
        .await
        .expect("deploy contract")
        .0;

    // Insert multiple values with same key
    invoke_contract(
        &mut chain_state,
        &contract_hash,
        InvokeContract::Entry(0),
        vec![
            ValueCell::Bytes("mykey".as_bytes().to_vec()),
            ValueCell::Bytes("value1".as_bytes().to_vec()),
            ValueCell::Bytes("value2".as_bytes().to_vec()),
            ValueCell::Bytes("value3".as_bytes().to_vec()),
        ],
    )
    .await
    .expect("insert multiple");

    // Get first value (should be bytes(1) due to insertion order)
    let result = invoke_contract(
        &mut chain_state,
        &contract_hash,
        InvokeContract::Entry(1),
        vec![ValueCell::Bytes("mykey".as_bytes().to_vec())],
    )
    .await
    .expect("get first");

    assert!(result.is_success(), "get first should succeed: {:?}", result);

    let ExitValue::Payload(ValueCell::Bytes(payload)) = result.exit_value else {
        panic!("invalid exit value");
    };
    assert!(payload == b"value1".to_vec(), "first value should be value1");

    // Delete first and get next value
    let result = invoke_contract(
        &mut chain_state,
        &contract_hash,
        InvokeContract::Entry(2),
        vec![ValueCell::Bytes("mykey".as_bytes().to_vec())],
    )
    .await
    .expect("delete and get next");

    assert!(result.is_success(), "delete and get next should succeed: {:?}", result);

    let ExitValue::Payload(ValueCell::Bytes(payload)) = result.exit_value else {
        panic!("invalid exit value");
    };

    assert!(payload == b"value2".to_vec(), "next value should be value2");
}

/// Test internal mutability: modifying a value after retrieval should NOT affect storage
#[tokio::test]
async fn test_btree_internal_mutability() {
    // This test demonstrates that BTree values are stored by value and changes
    // to the retrieved value don't affect the original stored value
    let code = r#"
        struct Foo {
            data: u64[]
        }

        entry get_and_verify() {
            let foo = Foo { data: [1, 2, 3] };
            let store = BTreeStore::new(b"ns");
            store.insert(b"key", foo);
            foo.data[0] = 42; // Modify retrieved value

            let tmp: Foo = store.get(b"key").unwrap();
            assert(tmp != foo);
            // Modify again to verify it's a different instance
            tmp.data[0] = 100;

            let tmp2: Foo = store.get(b"key").unwrap();
            assert(tmp2.data[0] == 1); // Original value should remain unchanged

            return 0
        }
    "#;

    let mut chain_state = MockChainState::new();
    let contract_hash = deploy_contract(&mut chain_state, code, ContractVersion::V1)
        .await
        .expect("deploy contract")
        .0;

    // Store data
    let result = invoke_contract(
        &mut chain_state,
        &contract_hash,
        InvokeContract::Entry(0),
        vec![],
    )
    .await
    .expect("store data");

    assert!(result.is_success(), "get and verify should succeed: {:?}", result);
}

/// Test BTree with different namespaces maintain separate stores
#[tokio::test]
async fn test_btree_different_namespaces() {
    let code = r#"
        entry insert_to_store1(namespace: bytes) {
            let store = BTreeStore::new(namespace);
            assert(store.get(b"key").is_none());
            store.insert(b"key", b"value");
            return 0
        }
    "#;

    let mut chain_state = MockChainState::new();
    let contract_hash = deploy_contract(&mut chain_state, code, ContractVersion::V1)
        .await
        .expect("deploy contract")
        .0;

    for i in 0..5 {
        let ns = format!("ns{}", i);
        let result = invoke_contract(
            &mut chain_state,
            &contract_hash,
            InvokeContract::Entry(0),
            vec![ValueCell::Bytes(ns.as_bytes().to_vec())],
        )
        .await
        .expect("insert to store");

        assert!(result.is_success(), "insert to store should succeed: {:?}", result);
    }

}

/// Test BTree cursor operations (seek)
#[tokio::test]
async fn test_btree_cursor_seek() {
    let code = r#"
        entry cursor_test() {
            let store = BTreeStore::new(b"ns");

            foreach i in 0..10 {
                store.insert(b"key", b"value");
            }

            let count = 0;
            let (cursor, entry) = store.seek(b"key", BTreeSeekBias::GreaterOrEqual, true);
            while entry.is_some() {
                count += 1;
                let e = entry.unwrap();
                assert(e.key == b"key");
                assert(e.value == b"value");

                entry = cursor.next();
            }

            assert(count == 10);

            return 0
        }
    "#;

    let mut chain_state = MockChainState::new();
    let contract_hash = deploy_contract(&mut chain_state, code, ContractVersion::V1)
        .await
        .expect("deploy contract")
        .0;

    // Insert values
    let result = invoke_contract(
        &mut chain_state,
        &contract_hash,
        InvokeContract::Entry(0),
        vec![],
    )
    .await
    .expect("insert values");

    assert!(result.is_success(), "insert values should succeed: {:?}", result);
}