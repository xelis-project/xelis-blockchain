use super::*;

#[tokio::test]
async fn test_insert_and_get() {
    let code = r#"
        struct Foo {
            value: u64[]
        }

        entry insert_value() {
            let foo = Foo {
                value: [1, 2, 3]
            };
            let storage = Storage::new();
            require(storage.store(b"key", foo).is_none(), "Key already exists");
            foo.value = [4, 5, 6];

            let tmp: Foo = storage.load(b"key").unwrap();
            assert(tmp.value == [1, 2, 3]);
            tmp.value = [7, 8, 9];

            let tmp2: Foo = storage.load(b"key").unwrap();
            assert(tmp2.value == [1, 2, 3]);

            return 0
        }

        entry get_value() {
            let storage = Storage::new();
            let value: Foo = storage.load(b"key").unwrap();
            assert(value.value == [1, 2, 3]);
            return 0
        }
    "#;

    let mut chain_state = MockChainState::with(BlockVersion::V6);
    let contract_hash = deploy_contract(&mut chain_state, code, ContractVersion::V1)
        .await
        .expect("deploy contract")
        .0;

    let result = invoke_contract(
        &mut chain_state,
        &contract_hash,
        InvokeContract::Entry(0),
        vec![],
    )
    .await
    .expect("insert value");

    assert!(result.is_success(), "insert should succeed: {:?}", result);

    let key = ValueCell::Bytes(b"key".to_vec());
    let storage = &chain_state.contract_caches.get(&contract_hash)
        .expect("contract cache")
        .storage;
    assert!(storage.len() == 1, "storage should have 1 entry after insert");
    assert!(matches!(storage.get(&key), Some(&Some((VersionedState::New, Some(_))))), "storage should contain the inserted key");

    let result = invoke_contract(
        &mut chain_state,
        &contract_hash,
        InvokeContract::Entry(1),
        vec![],
    )
    .await
    .expect("get value");

    assert!(result.is_success(), "get should succeed: {:?}", result);

    let storage = &chain_state.contract_caches.get(&contract_hash)
        .expect("contract cache")
        .storage;
    let value = storage.get(&key)
        .expect("key should exist in storage")
        .as_ref()
        .expect("value should be present")
        .1
        .as_ref()
        .expect("value should be Some");

    let values: Vec<_> = value
        .as_vec()
        .unwrap()
        [0]
        .as_ref()
        .as_vec()
        .unwrap()
        .iter()
        .map(|v| v.as_ref().as_u64().unwrap())
        .collect();
    assert!(values == vec![1, 2, 3]);
}

#[tokio::test]
async fn test_store_overwrite_delete_and_missing_keys() {
    let code = r#"
        entry mutate() {
            let storage = Storage::new();

            require(!storage.has(b"key"), "key should not exist");
            require(storage.load(b"key") == null, "missing key should load null");
            require(storage.delete(b"key") == null, "missing delete should return null");

            require(storage.store(b"key", 10) == null, "first store should return null");
            require(storage.has(b"key"), "key should exist");
            require(storage.load(b"key").expect("stored value") == 10, "bad stored value");

            require(storage.store(b"key", 20).expect("previous value") == 10, "overwrite should return previous value");
            require(storage.load(b"key").expect("updated value") == 20, "bad updated value");

            require(storage.delete(b"key").expect("deleted value") == 20, "delete should return previous value");
            require(!storage.has(b"key"), "key should be deleted");
            require(storage.load(b"key") == null, "deleted key should load null");
            require(storage.delete(b"key") == null, "second delete should return null");

            return 0
        }
    "#;

    let mut chain_state = MockChainState::with(BlockVersion::V6);
    let contract_hash = deploy_contract(&mut chain_state, code, ContractVersion::V1)
        .await
        .expect("deploy contract")
        .0;

    let result = invoke_contract(
        &mut chain_state,
        &contract_hash,
        InvokeContract::Entry(0),
        vec![],
    )
    .await
    .expect("mutate storage");

    assert!(result.is_success(), "storage mutation should succeed: {:?}", result);

    let storage = &chain_state.contract_caches.get(&contract_hash)
        .expect("contract cache")
        .storage;
    assert!(
        storage.get(&ValueCell::Bytes(b"key".to_vec())).is_none_or(|entry| {
            entry.as_ref().is_none_or(|(_, value)| value.is_none())
        }),
        "deleted key should not persist with a value"
    );
}

#[tokio::test]
async fn test_storage_changes_rollback_on_failed_execution() {
    let code = r#"
        entry fail_after_store() {
            let storage = Storage::new();
            storage.store(b"key", 99);
            require(false, "forced failure");
            return 0
        }

        entry verify_empty() {
            let storage = Storage::new();
            require(!storage.has(b"key"), "failed execution must not persist storage");
            require(storage.load(b"key") == null, "failed execution value must be null");
            return 0
        }
    "#;

    let mut chain_state = MockChainState::with(BlockVersion::V6);
    let contract_hash = deploy_contract(&mut chain_state, code, ContractVersion::V1)
        .await
        .expect("deploy contract")
        .0;

    let failed = invoke_contract(
        &mut chain_state,
        &contract_hash,
        InvokeContract::Entry(0),
        vec![],
    )
    .await
    .expect("invoke failed storage");

    assert!(!failed.is_success(), "forced failure should fail: {:?}", failed);

    let verify = invoke_contract(
        &mut chain_state,
        &contract_hash,
        InvokeContract::Entry(1),
        vec![],
    )
    .await
    .expect("verify empty storage");

    assert!(verify.is_success(), "failed storage writes should roll back: {:?}", verify);
}