use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use futures::{future::pending, poll};
use xelis_vm::{EnvironmentError, FunctionHandler, NativeScope, NativeState, VMContext};
use crate::{contract::{build_environment, ModuleMetadata}, transaction::mock::MockStorageProvider};

#[tokio::test]
async fn failed_execution_retains_only_legacy_shared_child_mutations() {
    let code = r#"
        struct Foo { values: u64[] }
        entry seed() {
            let storage = Storage::new();
            storage.store(b"items", Foo { values: [1] });
            storage.store(b"deleted", Foo { values: [1] });
            storage.store(b"unrelated", Foo { values: [1] });
            storage.store(b"counter", 0);
            return 0
        }
        entry fail(mode: u8) {
            let storage = Storage::new();
            let items: Foo = storage.load(b"items").unwrap();
            storage.store(b"items", Foo { values: [7] });
            items.values[0] = 99;
            let deleted: Foo = storage.delete(b"deleted").unwrap();
            deleted.values[0] = 88;
            storage.store(b"counter", 1);
            storage.store(b"inserted", 42);
            if mode == 0 { return 1 }
            require(false, "forced rollback");
            return 0
        }
        entry verify(expected: u64, expected_deleted: u64) {
            let storage = Storage::new();
            let items: Foo = storage.load(b"items").unwrap();
            let deleted: Foo = storage.load(b"deleted").unwrap();
            let unrelated: Foo = storage.load(b"unrelated").unwrap();
            require(items.values[0] == expected, "incorrect replaced child rollback");
            require(deleted.values[0] == expected_deleted, "incorrect deleted child rollback");
            require(unrelated.values[0] == 1, "unrelated value changed");
            require(storage.load(b"counter").unwrap() == 0, "replacement leaked");
            require(!storage.has(b"inserted"), "insertion leaked");
            return 0
        }
    "#;
    for mode in [0u8, 1u8] {
        for version in [BlockVersion::V5, BlockVersion::V6, BlockVersion::V7] {
            let mut state = MockChainState::with(version);
            let contract = create_contract(&mut state, code, ContractVersion::V0).unwrap();
            let seed = invoke_contract(&mut state, &contract, InvokeContract::Entry(0), vec![]).await.unwrap();
            assert!(seed.is_success(), "seed: {:?}", seed);
            let key = OwnedValue::Bytes(b"items".to_vec());
            state.contract_caches.get_mut(&contract).unwrap().storage.get_mut(&key).unwrap()
                .as_mut().unwrap().0 = VersionedState::FetchedAt(7);
            let failure = invoke_contract(&mut state, &contract, InvokeContract::Entry(1), vec![mode.into()]).await.unwrap();
            assert!(!failure.is_success(), "failure: {:?}", failure);
            assert_eq!(state.contract_caches[&contract].storage[&key].as_ref().unwrap().0, VersionedState::FetchedAt(7));
            let (expected, deleted) = if version < BlockVersion::V6 { (99u64, 88u64) } else { (1u64, 1u64) };
            let verify = invoke_contract(&mut state, &contract, InvokeContract::Entry(2), vec![expected.into(), deleted.into()]).await.unwrap();
            assert!(verify.is_success(), "{:?}, mode {}: {:?}", version, mode, verify);
        }
    }
}

#[tokio::test]
async fn repeated_loads_share_legacy_children_but_not_root_shape() {
    let code = r#"
        entry seed() { Storage::new().store(b"items", [1]); return 0 }
        entry mutate(expected: u64) {
            let storage = Storage::new();
            let items: u64[] = storage.load(b"items").unwrap();
            items[0] = 99;
            items.push(7);
            let again: u64[] = storage.load(b"items").unwrap();
            require(again.len() == 1, "root shape leaked between loads");
            require(again[0] == expected, "incorrect aliasing between loads");
            return 0
        }
        entry verify(expected: u64) {
            let items: u64[] = Storage::new().load(b"items").unwrap();
            require(items.len() == 1, "root shape persisted");
            require(items[0] == expected, "incorrect mutation export");
            return 0
        }
    "#;
    for version in [BlockVersion::V5, BlockVersion::V6] {
        let mut state = MockChainState::with(version);
        let contract = create_contract(&mut state, code, ContractVersion::V0).unwrap();
        let seed = invoke_contract(&mut state, &contract, InvokeContract::Entry(0), vec![]).await.unwrap();
        assert!(seed.is_success(), "seed: {:?}", seed);
        let expected = if version < BlockVersion::V6 { 99u64 } else { 1u64 };
        for entry in [1, 2] {
            let result = invoke_contract(&mut state, &contract, InvokeContract::Entry(entry), vec![expected.into()]).await.unwrap();
            assert!(result.is_success(), "{:?}, entry {}: {:?}", version, entry, result);
        }
    }
}

static WAIT_ENTERED: AtomicBool = AtomicBool::new(false);

fn resume(_: NativeState, _: &mut NativeScope<'_, ContractMetadata>) -> Result<(), EnvironmentError> { Ok(()) }

fn wait(scope: &mut NativeScope<'_, ContractMetadata>, _: &ModuleMetadata<'_>, _: &mut VMContext) -> Result<(), EnvironmentError> {
    WAIT_ENTERED.store(true, Ordering::SeqCst);
    scope.await_and_resume(Box::pin(pending()), &[], Box::new(()), resume);
    Ok(())
}

#[tokio::test]
async fn cancelled_vm_scope_releases_legacy_storage_without_exporting() {
    let code = r#"
        entry seed() { Storage::new().store(b"items", [1]); return 0 }
        entry suspend() {
            let items: u64[] = Storage::new().load(b"items").unwrap();
            items[0] = 99;
            pause();
            return 0
        }
    "#;
    let mut state = MockChainState::with(BlockVersion::V5);
    let mut builder = build_environment::<MockStorageProvider>(ContractVersion::V0);
    builder.register_native_function("pause", None, vec![], FunctionHandler::Sync(wait), 0, None);
    state.environments.insert(ContractVersion::V0, Arc::new(builder.environment().clone()));
    state.env_builders.insert(ContractVersion::V0, Arc::new(builder));
    let contract = create_contract(&mut state, code, ContractVersion::V0).unwrap();
    let seed = invoke_contract(&mut state, &contract, InvokeContract::Entry(0), vec![]).await.unwrap();
    assert!(seed.is_success(), "seed: {:?}", seed);
    let caller = ContractCaller::System;
    let (environment, mut chain_state) = state.get_contract_environment_for(
        Cow::Borrowed(&contract), None, caller.clone(), Default::default(),
    ).await.unwrap();
    let mut execution = Box::pin(vm::run_virtual_machine(
        environment, &mut chain_state, &caller, InvokeContract::Entry(1), Cow::Borrowed(&contract),
        IndexMap::new(), vec![].into_iter(), 1_000_000,
    ));
    assert!(poll!(execution.as_mut()).is_pending());
    assert!(WAIT_ENTERED.load(Ordering::SeqCst), "VM must reach the suspended native");
    drop(execution);
    let key = OwnedValue::Bytes(b"items".to_vec());
    assert_eq!(chain_state.global_caches[&contract].storage[&key].as_ref().unwrap().1,
        Some(OwnedValue::Object(vec![1u64.into()])));
}

#[tokio::test]
async fn scoped_native_and_callback_mutations_preserve_gas() {
    let code = r#"
        struct Foo { values: u64[] }
        entry seed() { Storage::new().store(b"items", Foo { values: [3, 1, 2] }); return 0 }
        entry mutate(mode: u8, fail: bool) {
            let items: Foo = Storage::new().load(b"items").unwrap();
            if mode == 0 { items.values.reverse(); }
            else if mode == 1 { items.values.sort_by_key(|value: u64| { return value }, true); }
            else { items.values[0] += 9; items.values[1] += 1; }
            if fail { return 1 }
            return 0
        }
    "#;
    for mode in 0..3u8 {
        for fail in [false, true] {
            let mut gas = Vec::new();
            for version in [BlockVersion::V5, BlockVersion::V6] {
                let mut state = MockChainState::with(version);
                let contract = create_contract(&mut state, code, ContractVersion::V0).unwrap();
                let seed = invoke_contract(&mut state, &contract, InvokeContract::Entry(0), vec![]).await.unwrap();
                assert!(seed.is_success(), "seed: {:?}", seed);
                let result = invoke_contract(&mut state, &contract, InvokeContract::Entry(1), vec![mode.into(), fail.into()]).await.unwrap();
                assert_eq!(result.is_success(), !fail, "mutation: {:?}", result);
                gas.push(result.used_gas);
                let expected: Vec<u64> = if version >= BlockVersion::V6 { vec![3, 1, 2] } else {
                    match mode { 0 => vec![2, 1, 3], 1 => vec![1, 2, 3], _ => vec![12, 2, 2] }
                };
                let expected = OwnedValue::Object(vec![OwnedValue::Object(expected.into_iter().map(OwnedValue::from).collect())]);
                let key = OwnedValue::Bytes(b"items".to_vec());
                assert_eq!(state.contract_caches[&contract].storage[&key].as_ref().unwrap().1, Some(expected));
            }
            assert_eq!(gas[0], gas[1], "scope changed gas: mode {}, fail {}", mode, fail);
        }
    }
}

#[tokio::test]
async fn scoped_payload_success_commits_storage() {
    // Direct VM tests can invoke V1 in a legacy block; export must use the same
    // success rules as payload validation, rather than only accepting numeric zero.
    let code = r#"
        entry main() -> bytes {
            Storage::new().store(b"items", [1]);
            let items: u64[] = Storage::new().load(b"items").unwrap();
            items[0] = 99;
            return b"ok"
        }
    "#;
    let mut state = MockChainState::with(BlockVersion::V5);
    let contract = create_contract(&mut state, code, ContractVersion::V1).unwrap();
    let result = invoke_contract(&mut state, &contract, InvokeContract::Entry(0), vec![]).await.unwrap();
    assert!(result.is_success(), "payload: {:?}", result);
    let key = OwnedValue::Bytes(b"items".to_vec());
    assert_eq!(state.contract_caches[&contract].storage[&key].as_ref().unwrap().1, Some(OwnedValue::Object(vec![99u64.into()])));
}

#[tokio::test]
async fn payload_gas_failure_does_not_commit_storage_writes() {
    let code = r#"
        entry seed() { Storage::new().store(b"counter", 0); return 0 }
        entry main() -> bytes {
            Storage::new().store(b"counter", 1);
            return b"payload"
        }
    "#;
    let mut full_gas = None;
    for limited in [false, true] {
        let mut state = MockChainState::with(BlockVersion::V5);
        let contract = create_contract(&mut state, code, ContractVersion::V1).unwrap();
        let seed = invoke_contract(&mut state, &contract, InvokeContract::Entry(0), vec![]).await.unwrap();
        assert!(seed.is_success(), "seed: {:?}", seed);
        let max_gas = if limited { full_gas.unwrap() - 1 } else { 1_000_000 };
        let result = vm::invoke_contract(
            ContractCaller::System, &mut state, Cow::Borrowed(&contract), None,
            vec![].into_iter(), IndexMap::new(), max_gas, InvokeContract::Entry(1),
            Cow::Owned(InterContractPermission::default()), true,
        ).await.unwrap();
        assert_eq!(result.is_success(), !limited, "limited {}: {:?}", limited, result);
        if !limited { full_gas = Some(result.used_gas); }
        let key = OwnedValue::Bytes(b"counter".to_vec());
        let expected = if limited { 0u64 } else { 1u64 };
        assert_eq!(state.contract_caches[&contract].storage[&key].as_ref().unwrap().1, Some(expected.into()));
    }
}
