use crate::{block::BlockVersion, versioned::VersionedState};

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

    // Get the value back
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