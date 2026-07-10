use super::*;

#[tokio::test]
async fn test_read_only_storage_can_read_other_contract_without_mutating_it() {
    let writer_code = r#"
        entry write() {
            let storage = Storage::new();
            storage.store(b"key", 42);
            storage.store(b"other", "value");
            return 0
        }
    "#;
    let reader_code = r#"
        entry read(target: Hash) {
            let storage = ReadOnlyStorage::new(target).expect("read only storage");

            require(storage.has(b"key"), "target key should exist");
            require(storage.load(b"key").expect("target value") == 42, "bad target value");
            require(storage.load(b"other").expect("other value") == "value", "bad string value");
            require(!storage.has(b"missing"), "missing key should not exist");
            require(storage.load(b"missing") == null, "missing key should load null");

            return 0
        }
    "#;

    let mut chain_state = MockChainState::with(BlockVersion::V6);
    let writer = deploy_contract(&mut chain_state, writer_code, ContractVersion::V1)
        .await
        .expect("deploy writer")
        .0;
    let reader = deploy_contract(&mut chain_state, reader_code, ContractVersion::V1)
        .await
        .expect("deploy reader")
        .0;

    let write = invoke_contract(
        &mut chain_state,
        &writer,
        InvokeContract::Entry(0),
        vec![],
    )
    .await
    .expect("write target storage");
    assert!(write.is_success(), "writer should succeed: {:?}", write);

    let read = invoke_contract(
        &mut chain_state,
        &reader,
        InvokeContract::Entry(0),
        vec![Primitive::Opaque(writer.clone().into()).into()],
    )
    .await
    .expect("read target storage");
    assert!(read.is_success(), "read only storage should read target: {:?}", read);

    let writer_storage = &chain_state.contract_caches.get(&writer)
        .expect("writer cache")
        .storage;
    assert_eq!(
        writer_storage
            .get(&ValueCell::Bytes(b"key".to_vec()))
            .and_then(|entry| entry.as_ref())
            .and_then(|(_, value)| value.as_ref())
            .and_then(|value| value.as_u64().ok()),
        Some(42),
        "read only access should not alter target value"
    );
    assert_eq!(
        writer_storage
            .get(&ValueCell::Bytes(b"other".to_vec()))
            .and_then(|entry| entry.as_ref())
            .and_then(|(_, value)| value.as_ref())
            .and_then(|value| value.as_string().ok()),
        Some("value"),
        "read only access should not alter target string value"
    );
}

#[tokio::test]
async fn test_read_only_storage_new_returns_null_for_unknown_contract() {
    let code = r#"
        entry main(target: Hash) {
            require(ReadOnlyStorage::new(target) == null, "unknown contract should return null");
            return 0
        }
    "#;

    let mut chain_state = MockChainState::with(BlockVersion::V6);
    let contract_hash = deploy_contract(&mut chain_state, code, ContractVersion::V1)
        .await
        .expect("deploy contract")
        .0;

    let unknown = Hash::new([42u8; 32]);
    let result = invoke_contract(
        &mut chain_state,
        &contract_hash,
        InvokeContract::Entry(0),
        vec![Primitive::Opaque(unknown.into()).into()],
    )
    .await
    .expect("unknown read only storage");

    assert!(result.is_success(), "unknown read only storage should return null: {:?}", result);
}

#[tokio::test]
async fn test_read_only_storage_reads_own_cache_changes() {
    let code = r#"
        entry main() {
            let storage = Storage::new();
            storage.store(b"key", 123);

            let readonly = ReadOnlyStorage::new(get_contract_hash()).expect("self read only storage");
            require(readonly.has(b"key"), "read only storage should see current cache");
            require(readonly.load(b"key").expect("value") == 123, "bad read only value");

            storage.delete(b"key");
            require(!readonly.has(b"key"), "read only storage should see deletion");
            require(readonly.load(b"key") == null, "deleted value should be null");

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
    .expect("self read only storage");

    assert!(result.is_success(), "self read only storage should see cache changes: {:?}", result);
}

#[tokio::test]
async fn test_read_only_storage_rejects_reserved_btree_keys() {
    let target_code = r#"
        entry main() {
            return 0
        }
    "#;
    let reader_code = r#"
        entry check_has(target: Hash, key: any) {
            let storage = ReadOnlyStorage::new(target).expect("read only storage");
            storage.has(key);
            return 0
        }

        entry check_load(target: Hash, key: any) {
            let storage = ReadOnlyStorage::new(target).expect("read only storage");
            storage.load(key);
            return 0
        }
    "#;

    let mut chain_state = MockChainState::with(BlockVersion::V6);
    let target = deploy_contract(&mut chain_state, target_code, ContractVersion::V1)
        .await
        .expect("deploy target")
        .0;
    let reader = deploy_contract(&mut chain_state, reader_code, ContractVersion::V1)
        .await
        .expect("deploy reader")
        .0;

    let reserved_key = || {
        let mut bytes = Vec::from([0u8]);
        bytes.extend_from_slice(b"btree:orders:root");
        ValueCell::Bytes(bytes)
    };

    let has = invoke_contract(
        &mut chain_state,
        &reader,
        InvokeContract::Entry(0),
        vec![Primitive::Opaque(target.clone().into()).into(), reserved_key()],
    )
    .await
    .expect("read only has reserved key");
    assert!(!has.is_success(), "read only has must reject reserved BTree keys: {:?}", has);

    let load = invoke_contract(
        &mut chain_state,
        &reader,
        InvokeContract::Entry(1),
        vec![Primitive::Opaque(target.into()).into(), reserved_key()],
    )
    .await
    .expect("read only load reserved key");
    assert!(!load.is_success(), "read only load must reject reserved BTree keys: {:?}", load);
}
