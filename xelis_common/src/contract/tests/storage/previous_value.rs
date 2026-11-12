use super::*;
use crate::contract::{ContractCache, ExitError, vm::ExitValue};

#[tokio::test]
async fn store_delete_previous_values_are_independent_of_cache_and_prior_reads() {
    let code = r#"
        entry main(operation: u8, warm: u8, present: bool, mode: u8) {
            let storage = Storage::new();
            if warm == 1 {
                require(storage.has(b"key") == present, "incorrect has before mutation");
            }
            if warm == 2 {
                require(storage.load(b"key").is_some() == present, "incorrect load before mutation");
            }
            let previous: optional<any> = null;
            if operation == 0 {
                previous = storage.store(b"key", 99);
            } else {
                previous = storage.delete(b"key");
            }
            if present {
                require(previous.unwrap() == 42, "incorrect previous value");
            } else {
                require(previous.is_none(), "absent value must return null");
            }
            if operation == 0 {
                require(storage.load(b"key").unwrap() == 99, "store did not apply");
                require(storage.store(b"key", 100).unwrap() == 99, "overwrite returned stale provider value");
            } else {
                require(!storage.has(b"key"), "delete did not apply");
                require(storage.delete(b"key").is_none(), "repeated delete returned stale provider value");
                require(storage.store(b"key", 77).is_none(), "reinsertion returned deleted provider value");
                require(storage.delete(b"key").unwrap() == 77, "delete after reinsertion returned stale value");
                require(storage.delete(b"key").is_none(), "second repeated delete returned stale value");
            }
            if mode == 1 { return 1 }
            if mode == 2 { require(false, "forced failure"); }
            return 0
        }
    "#;

    for block in [BlockVersion::V5, BlockVersion::V6, BlockVersion::V7] {
        for version in [ContractVersion::V0, ContractVersion::V1] {
            // Existing value, persisted deletion, and a key with no version.
            for persisted in [Some(Some(42u64)), Some(None), None] {
                for cached in [false, true] {
                    for warm in 0..3u8 {
                        for operation in 0..2u8 {
                            for mode in 0..3u8 {
                                let mut state = MockChainState::with(block);
                                let contract = create_contract(&mut state, code, version).unwrap();
                                let key = OwnedValue::Bytes(b"key".to_vec());
                                let value = persisted.map(|value| value.map(OwnedValue::from));
                                if let Some(value) = &value {
                                    state.provider.contracts.entry(contract.clone()).or_default()
                                        .insert(key.clone(), (7, value.clone()));
                                }
                                if cached {
                                    let mut cache = ContractCache::default();
                                    cache.storage.insert(key.clone(), value.clone()
                                        .map(|value| (VersionedState::FetchedAt(7), value)));
                                    state.contract_caches.insert(contract.clone(), cache);
                                }
                                let original_provider = state.provider.contracts.clone();
                                let original_cache = state.contract_caches.get(&contract).map(|cache| cache.storage.clone());
                                let result = invoke_contract(&mut state, &contract, InvokeContract::Entry(0), vec![
                                    operation.into(), warm.into(), matches!(persisted, Some(Some(_))).into(), mode.into(),
                                ]).await.unwrap();
                                let reached_exit = match (&result.exit_value, mode) {
                                    (ExitValue::ExitCode(0), 0) | (ExitValue::ExitCode(1), 1) => true,
                                    (ExitValue::Error(ExitError::RuntimeError(message)), 2) => message.contains("forced failure"),
                                    _ => false,
                                };
                                assert!(reached_exit,
                                    "{:?}, {:?}, persisted {:?}, cached {}, warm {}, operation {}, mode {}: {:?}",
                                    block, version, persisted, cached, warm, operation, mode, result);
                                assert_eq!(state.provider.contracts, original_provider, "VM must not mutate the provider");
                                if mode != 0 {
                                    assert_eq!(state.contract_caches.get(&contract).map(|cache| cache.storage.clone()), original_cache,
                                        "failed execution must preserve values and version metadata");
                                } else {
                                    let stored = state.contract_caches[&contract].storage.get(&key);
                                    let expected_version = if persisted.is_some() { VersionedState::Updated(7) } else { VersionedState::New };
                                    if operation == 0 {
                                        assert_eq!(stored, Some(&Some((expected_version, Some(100u64.into())))));
                                    } else if persisted.is_some() {
                                        assert_eq!(stored, Some(&Some((expected_version, None))));
                                    } else {
                                        assert!(stored.is_none_or(|entry| entry.is_none()), "deleting a new entry must not persist a tombstone");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
