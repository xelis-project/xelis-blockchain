use super::*;
use crate::contract::{ExitError, vm::{ExecutionResult, ExitValue}};

// Exercise heap-backed descendants and a serializable opaque with mutating natives.
// Every mutation has a positive control so a no-op cannot make isolation pass.
const PAYLOAD: &str = r#"
    struct Payload {
        rows: u64[][],
        values: map<u64, u64[]>,
        raw: bytes,
        point: RistrettoPoint
    }

    fn fresh() -> Payload {
        let values: map<u64, u64[]> = {};
        values.insert(7, [3, 1, 2]);
        return Payload {
            rows: [[3, 1, 2]], values: values,
            raw: b"abc", point: RistrettoPoint::identity()
        }
    }

    fn verify(value: Payload) {
        require(value.rows.len() == 1, "outer array changed");
        require(value.rows[0] == [3, 1, 2], "nested array changed");
        require(value.values.len() == 1, "map shape changed");
        require(value.values.get(7).unwrap() == [3, 1, 2], "map child changed");
        require(value.raw == b"abc", "bytes changed");
        require(value.point.is_identity(), "opaque changed");
    }

    fn mutate(value: Payload) {
        value.rows[0].reverse();
        value.rows[0].sort_by_key(|item: u64| { return item }, true);
        value.rows[0][0] = 99;
        value.rows[0].push(4);
        value.rows.push([5]);
        let child = value.values.get(7).unwrap();
        child[0] = 88;
        value.values.insert(8, [6]);
        value.raw.push(100u8);
        let returned = value.point.add_scalar(Scalar::ONE);
        require(!returned.is_identity(), "opaque native did not mutate");
        require(value.rows[0][0] == 99, "nested mutation did not happen");
        require(value.values.get(7).unwrap()[0] == 88, "map child mutation did not happen");
        require(value.raw == b"abcd", "byte mutation did not happen");
    }
"#;

// Keep the contract and storage contents, but force the next execution through
// ContractStorage::load_data instead of the global execution cache.
fn move_to_provider(state: &mut MockChainState, contract: &Hash) {
    let entries = state.contract_caches.get_mut(contract).unwrap().storage.drain()
        .filter_map(|(key, entry)| entry.map(|(_, value)| (key, (7, value))))
        .collect();
    state.provider.contracts.insert(contract.clone(), entries);
}

async fn run_entry(state: &mut MockChainState, contract: &Hash, entry: usize, params: Vec<OwnedValue>) -> ExecutionResult {
    let module = &state.contracts[&Cow::Borrowed(contract)].as_ref().unwrap().1.as_ref().unwrap().module;
    let chunk = (0..module.chunks().len()).filter(|index| module.is_entry_chunk(*index))
        .nth(entry).expect("entry ordinal") as u16;
    invoke_contract(state, contract, InvokeContract::Entry(chunk), params).await.unwrap()
}

fn assert_mode_result(result: &ExecutionResult, mode: u8, case: String) {
    match (&result.exit_value, mode) {
        (ExitValue::ExitCode(0), 0) | (ExitValue::ExitCode(1), 1) => {},
        (ExitValue::Error(ExitError::RuntimeError(message)), 2) if message.contains("forced failure") => {},
        _ => panic!("{}, mode {} did not reach its intended exit: {:?}", case, mode, result),
    }
}

async fn run_success(state: &mut MockChainState, contract: &Hash, entry: usize, params: Vec<OwnedValue>) {
    let result = run_entry(state, contract, entry, params).await;
    assert!(result.is_success(), "entry {}: {:?}", entry, result);
}

#[tokio::test]
async fn read_only_storage_nested_mutations_never_change_the_target() {
    let code = [PAYLOAD, r#"
        entry seed() {
            let original = fresh();
            Storage::new().store(b"key", original);
            let local = ReadOnlyStorage::new(get_contract_hash()).unwrap();
            let loaded: Payload = local.load(b"key").unwrap();
            mutate(loaded);
            verify(original);
            let again: Payload = local.load(b"key").unwrap();
            verify(again);
            return 0
        }
        entry attack(target: Hash, mode: u8) {
            let storage = ReadOnlyStorage::new(target).unwrap();
            let first: Payload = storage.load(b"key").unwrap();
            let second: Payload = storage.load(b"key").unwrap();
            mutate(first);
            verify(second);
            let again: Payload = storage.load(b"key").unwrap();
            verify(again);
            if mode == 1 { return 1 }
            if mode == 2 { require(false, "forced failure"); }
            return 0
        }
        entry check() {
            let value: Payload = Storage::new().load(b"key").unwrap();
            verify(value);
            return 0
        }
    "#].concat();
    for block in [BlockVersion::V5, BlockVersion::V6, BlockVersion::V7] {
        for version in [ContractVersion::V0, ContractVersion::V1] {
            for provider in [false, true] {
                for own in [false, true] {
                    for mode in 0..3u8 {
                        let mut state = MockChainState::with(block);
                        let target = create_contract(&mut state, &code, version).unwrap();
                        let reader = if own { target.clone() } else {
                            create_contract(&mut state, &code, version).unwrap()
                        };
                        run_success(&mut state, &target, 0, vec![]).await;
                        let expected = state.contract_caches[&target].storage.clone();
                        if provider { move_to_provider(&mut state, &target); }
                        let original_provider = state.provider.contracts.clone();
                        let result = run_entry(&mut state, &reader, 1, vec![
                            OwnedValue::Opaque(target.clone().into()), mode.into(),
                        ]).await;
                        assert_mode_result(&result, mode, format!("{:?}, {:?}, provider {}, own {}", block, version, provider, own));
                        assert_eq!(state.provider.contracts, original_provider);
                        if !provider { assert_eq!(state.contract_caches[&target].storage, expected); }
                        run_success(&mut state, &target, 2, vec![]).await;
                    }
                }
            }
        }
    }
}

#[test]
fn read_only_storage_has_no_write_methods_or_storage_conversion() {
    for version in [ContractVersion::V0, ContractVersion::V1] {
        let state = MockChainState::with(BlockVersion::V6);
        let env = &state.env_builders[&version];
        for operation in [
            "storage.store(b\"key\", 1);",
            "storage.delete(b\"key\");",
            "storage.insert(b\"key\", 1);",
            "let writable: Storage = storage;",
            "let writable: BTreeStore = storage;",
        ] {
            let code = format!("entry main(target: Hash) {{ let storage = ReadOnlyStorage::new(target).unwrap(); {} return 0 }}", operation);
            let tokens = Lexer::new(&code).into_iter().collect::<Result<Vec<_>, _>>().unwrap();
            assert!(Parser::with(tokens.into_iter(), env).parse().is_err(),
                "{:?} accepted forbidden operation: {}", version, operation);
        }
    }
}

#[tokio::test]
async fn persistent_storage_v6_values_keys_and_previous_values_are_detached() {
    let code = [PAYLOAD, r#"
        entry seed() {
            let storage = Storage::new();
            let key = b"key";
            let original = fresh();
            storage.store(key, original);
            key.push(100u8);
            mutate(original);
            require(!storage.has(key), "stored key changed with input");
            let value: Payload = storage.load(b"key").unwrap();
            verify(value);
            storage.store(b"other", fresh());
            return 0
        }
        entry attack(mode: u8) {
            let storage = Storage::new();
            let first: Payload = storage.load(b"key").unwrap();
            let second: Payload = storage.load(b"key").unwrap();
            mutate(first);
            verify(second);
            let previous: Payload = storage.store(b"key", second).unwrap();
            mutate(previous);
            // delete returns the cached previous value; populate its read cache.
            let before_delete: Payload = storage.load(b"other").unwrap();
            verify(before_delete);
            let deleted: Payload = storage.delete(b"other").unwrap();
            storage.store(b"other", deleted);
            mutate(deleted);
            let again: Payload = storage.load(b"key").unwrap();
            verify(again);
            let other: Payload = storage.load(b"other").unwrap();
            verify(other);
            if mode == 1 { return 1 }
            if mode == 2 { require(false, "forced failure"); }
            return 0
        }
        entry check() {
            let storage = Storage::new();
            let first: Payload = storage.load(b"key").unwrap();
            let second: Payload = storage.load(b"other").unwrap();
            verify(first);
            verify(second);
            return 0
        }
    "#].concat();
    for block in [BlockVersion::V6, BlockVersion::V7] {
        for version in [ContractVersion::V0, ContractVersion::V1] {
            for provider in [false, true] {
                for mode in 0..3u8 {
                    let mut state = MockChainState::with(block);
                    let contract = create_contract(&mut state, &code, version).unwrap();
                    run_success(&mut state, &contract, 0, vec![]).await;
                    if provider { move_to_provider(&mut state, &contract); }
                    let original_provider = state.provider.contracts.clone();
                    let result = run_entry(&mut state, &contract, 1, vec![mode.into()]).await;
                    assert_mode_result(&result, mode, format!("{:?}, {:?}, provider {}", block, version, provider));
                    assert_eq!(state.provider.contracts, original_provider);
                    run_success(&mut state, &contract, 2, vec![]).await;
                }
            }
        }
    }
}

#[tokio::test]
async fn btree_values_and_cursor_entries_are_detached() {
    let code = [PAYLOAD, r#"
        entry seed() {
            let namespace = b"ns";
            let key = b"a";
            let store = BTreeStore::new(namespace);
            let original = fresh();
            store.insert(key, original);
            store.insert(b"b", original);
            namespace.push(100u8);
            key.push(100u8);
            mutate(original);
            require(BTreeStore::new(b"ns").len() == 2, "namespace changed with input");
            require(store.get(key).is_none(), "stored key changed with input");
            let first: Payload = store.get(b"a").unwrap();
            verify(first);
            return 0
        }
        entry attack(mode: u8) {
            let store = BTreeStore::new(b"ns");
            let loaded: Payload = store.get(b"a").unwrap();
            mutate(loaded);
            let (cursor, initial) = store.seek(b"a", BTreeSeekBias::Exact, true);
            let entry = initial.unwrap();
            entry.key.push(100u8);
            let initial_value: Payload = entry.value;
            mutate(initial_value);
            let next = cursor.next().unwrap();
            require(next.key == b"b", "cursor key changed");
            let next_value: Payload = next.value;
            verify(next_value);
            mutate(next_value);
            next.key.push(100u8);
            let (backwards, last) = store.seek(b"b", BTreeSeekBias::Exact, false);
            let last_value: Payload = last.unwrap().value;
            verify(last_value);
            let previous = backwards.next().unwrap();
            require(previous.key == b"a", "seek result changed stored key");
            let previous_value: Payload = previous.value;
            verify(previous_value);
            mutate(previous_value);
            if mode == 1 { return 1 }
            if mode == 2 { require(false, "forced failure"); }
            return 0
        }
        entry check() {
            let store = BTreeStore::new(b"ns");
            require(store.len() == 2, "tree shape changed");
            let first: Payload = store.get(b"a").unwrap();
            let second: Payload = store.get(b"b").unwrap();
            verify(first);
            verify(second);
            return 0
        }
    "#].concat();
    for block in [BlockVersion::V5, BlockVersion::V6, BlockVersion::V7] {
        for version in [ContractVersion::V0, ContractVersion::V1] {
            for provider in [false, true] {
                for mode in 0..3u8 {
                    let mut state = MockChainState::with(block);
                    let contract = create_contract(&mut state, &code, version).unwrap();
                    run_success(&mut state, &contract, 0, vec![]).await;
                    let expected = state.contract_caches[&contract].storage.clone();
                    if provider { move_to_provider(&mut state, &contract); }
                    let original_provider = state.provider.contracts.clone();
                    let result = run_entry(&mut state, &contract, 1, vec![mode.into()]).await;
                    assert_mode_result(&result, mode, format!("{:?}, {:?}, provider {}", block, version, provider));
                    assert_eq!(state.provider.contracts, original_provider);
                    if !provider { assert_eq!(state.contract_caches[&contract].storage, expected); }
                    run_success(&mut state, &contract, 2, vec![]).await;
                }
            }
        }
    }
}

#[tokio::test]
async fn memory_storage_local_and_shared_values_are_detached() {
    let code = [PAYLOAD, r#"
        entry seed(shared: bool) {
            let storage = MemoryStorage::new(shared);
            let key = b"key";
            let original = fresh();
            storage.store(key, original);
            key.push(100u8);
            mutate(original);
            require(!storage.has(key), "memory key changed with input");
            let first: Payload = storage.load(b"key").unwrap();
            let second: Payload = storage.load(b"key").unwrap();
            verify(first);
            mutate(first);
            verify(second);
            let previous: Payload = storage.store(b"key", second).unwrap();
            mutate(previous);
            let deleted: Payload = storage.delete(b"key").unwrap();
            storage.store(b"key", deleted);
            mutate(deleted);
            let again: Payload = storage.load(b"key").unwrap();
            verify(again);
            return 0
        }
        entry attack(mode: u8) {
            let storage = MemoryStorage::new(true);
            let loaded: Payload = storage.load(b"key").unwrap();
            mutate(loaded);
            let again: Payload = storage.load(b"key").unwrap();
            verify(again);
            if mode == 1 { return 1 }
            if mode == 2 { require(false, "forced failure"); }
            return 0
        }
        entry check(shared: bool) {
            let storage = MemoryStorage::new(shared);
            if shared {
                let value: Payload = storage.load(b"key").unwrap();
                verify(value);
            } else {
                require(!storage.has(b"key"), "local memory persisted");
            }
            return 0
        }
    "#].concat();
    for block in [BlockVersion::V5, BlockVersion::V6, BlockVersion::V7] {
        for version in [ContractVersion::V0, ContractVersion::V1] {
            for shared in [false, true] {
                let mut state = MockChainState::with(block);
                let contract = create_contract(&mut state, &code, version).unwrap();
                run_success(&mut state, &contract, 0, vec![shared.into()]).await;
                if shared {
                    let expected = state.contract_caches[&contract].memory_shared.clone();
                    for mode in 0..3u8 {
                        let result = run_entry(&mut state, &contract, 1, vec![mode.into()]).await;
                        assert_mode_result(&result, mode, format!("{:?}, {:?}", block, version));
                        assert_eq!(state.contract_caches[&contract].memory_shared, expected);
                    }
                }
                run_success(&mut state, &contract, 2, vec![shared.into()]).await;
            }
        }
    }
}

#[tokio::test]
async fn storage_rejects_nonserializable_handles_and_nested_handles_without_panicking() {
    for version in [ContractVersion::V0, ContractVersion::V1] {
        for block in [BlockVersion::V5, BlockVersion::V6, BlockVersion::V7] {
            for handle in [
                "Storage::new()",
                "ReadOnlyStorage::new(get_contract_hash()).unwrap()",
                "BTreeStore::new(b\"ns\")",
                "cursor",
            ] {
                for value in ["handle", "[[handle]]", "items"] {
                    for write in [
                        "Storage::new().store(b\"key\", VALUE);",
                        "MemoryStorage::new(false).store(b\"key\", VALUE);",
                        "MemoryStorage::new(true).store(b\"key\", VALUE);",
                        "BTreeStore::new(b\"ns\").insert(b\"key\", VALUE);",
                    ] {
                        let code = r#"
                            entry seed() {
                                Storage::new().store(b"sentinel", 17);
                                return 0
                            }
                            entry reject() {
                                let (cursor, initial) = BTreeStore::new(b"ns").seek(b"key", BTreeSeekBias::Exact, true);
                                let handle = HANDLE;
                                let items: map<u64, any> = {};
                                items.insert(1, handle);
                                WRITE
                                return 0
                            }
                        "#.replace("HANDLE", handle).replace("WRITE", write).replace("VALUE", value);
                        let mut state = MockChainState::with(block);
                        let contract = create_contract(&mut state, &code, version).unwrap();
                        run_success(&mut state, &contract, 0, vec![]).await;
                        let expected = state.contract_caches[&contract].storage.clone();
                        let result = run_entry(&mut state, &contract, 1, vec![]).await;
                        assert!(matches!(&result.exit_value,
                            ExitValue::Error(ExitError::RuntimeError(message)) if message.contains("not serializable")),
                            "{:?}, {:?}, {}, {}, {}: {:?}", block, version, handle, value, write, result);
                        assert_eq!(state.contract_caches[&contract].storage, expected);
                        assert!(state.contract_caches[&contract].memory_shared.is_empty());
                    }
                }
            }
        }
    }
}
