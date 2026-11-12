use std::collections::HashMap;
use xelis_vm::{Heap, OwnedValue, RuntimeValue, ValueError, VMContext, tid};
use crate::crypto::Hash;
use super::{ChainState, ContractCache};

// Populated only inside a pre-V6 VM execution: original and current roots
// for accessed storage entries. Cleared before the execution heap is dropped.
#[derive(Default)]
pub(super) struct LegacyStorage {
    values: HashMap<(Hash, OwnedValue), (Option<RuntimeValue>, Option<RuntimeValue>)>,
}

tid!(LegacyStorage);

// SAFETY: trusted native functions use these runtime handles sequentially inside
// the VM's confined execution scope. The scope finalizer clears every handle
// before the heap is dropped, including cancellation.
unsafe impl Send for LegacyStorage {}
unsafe impl Sync for LegacyStorage {}

impl LegacyStorage {
    pub fn get(&self, contract: &Hash, key: &OwnedValue) -> Option<&Option<RuntimeValue>> {
        self.values.get(&(contract.clone(), key.clone()))
            .map(|(_, current)| current)
    }

    fn value(&mut self, contract: Hash, key: OwnedValue, value: Option<OwnedValue>, original: bool, heap: &mut Heap) -> RuntimeValue {
        let (_, current) = self.values.entry((contract, key))
            .or_insert_with(|| {
                let current = value.map(|value| heap.import_owned(value));
                (current.as_ref().filter(|_| original).cloned(), current)
            });

        current.clone().unwrap_or_default()
    }

    pub(crate) fn replace(&mut self, contract: Hash, key: OwnedValue, value: Option<OwnedValue>, heap: &mut Heap) {
        self.values.get_mut(&(contract, key)).expect("storage value was loaded").1 = value.map(|value| heap.import_owned(value));
    }

    // Export while the heap is alive. Result validation later chooses the current
    // values or the original shared children, without duplicating success rules.
    pub(crate) fn finish(self, heap: &Heap, state: &mut ChainState) -> Result<HashMap<Hash, ContractCache>, ValueError> {
        let mut snapshots = Vec::new();
        for ((contract, key), (original, current)) in self.values {
            snapshots.push((contract, key,
                original.as_ref().map(|value| heap.snapshot(value)).transpose()?,
                current.as_ref().map(|value| heap.snapshot(value)).transpose()?));
        }

        let mut originals: HashMap<Hash, ContractCache> = HashMap::new();
        for (contract, key, original, current) in snapshots {
            if let Some(Some((_, value))) = state.changes.caches.get_mut(&contract)
                .and_then(|cache| cache.storage.get_mut(&key)) {
                *value = current;
            }
            // Only original entries are returned. No full cache clone and no failed
            // insertion, deletion, replacement, balance, or version change is committed.
            if let Some(snapshot) = original {
                if let Some(Some((version, Some(_)))) = state.global_caches.get(&contract)
                    .and_then(|cache| cache.storage.get(&key)) {
                    originals.entry(contract).or_default().storage.insert(key, Some((*version, Some(snapshot))));
                }
            }
        }

        Ok(originals)
    }
}

pub(crate) fn storage_value(context: &mut VMContext, contract: Hash, key: OwnedValue, value: Option<OwnedValue>, heap: &mut Heap) -> RuntimeValue {
    let state = context.get::<ChainState>().expect("chain state initialized");
    let original = state.global_caches.get(&contract).and_then(|cache| cache.storage.get(&key))
        .and_then(|entry| entry.as_ref()).is_some_and(|(_, value)| value.is_some());
    match context.get_mut::<LegacyStorage>() {
        Some(storage) => storage.value(contract, key, value, original, heap),
        None => heap.import_owned(value.unwrap_or_default()),
    }
}

pub(crate) fn replace_storage_value(context: &mut VMContext, contract: Hash, key: OwnedValue, value: Option<OwnedValue>, heap: &mut Heap) {
    if let Some(storage) = context.get_mut::<LegacyStorage>() {
        storage.replace(contract, key, value, heap);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xelis_vm::{Module, PrimitiveInteger};
    use crate::{contract::{ContractModule, ContractVersion}, transaction::{mock::MockChainState, verify::BlockchainContractState}, versioned::VersionedState};
    use std::{borrow::Cow, sync::Arc};
    use crate::{block::BlockVersion, contract::vm::ContractCaller};

    #[tokio::test]
    async fn accessed_storage_exports_current_or_original_children_without_root_changes() {
        for success in [false, true] {
            for (overwrite, delete) in [(false, false), (true, false), (false, true), (true, true)] {
                let mut mock = MockChainState::with(BlockVersion::V5);
                let contract = Hash::zero();
                mock.internal_set_contract_module(contract.clone(), ContractModule {
                    module: Arc::new(Module::new()),
                    version: ContractVersion::V0,
                });
                let key = OwnedValue::Bytes(b"items".to_vec());
                let initial = OwnedValue::Object(vec![1u64.into()]);
                let mut cache = ContractCache::new();
                cache.storage.insert(key.clone(), Some((VersionedState::FetchedAt(7), Some(initial.clone()))));
                cache.storage.insert(8u64.into(), Some((VersionedState::New, Some(77u64.into()))));
                mock.contract_caches.insert(contract.clone(), cache.clone());
                // SAFETY: every runtime handle stays in this test's exclusive scope.
                let mut heap = unsafe { Heap::new() };
                let (_, mut state) = mock.get_contract_environment_for(
                    Cow::Borrowed(&contract), None, ContractCaller::System, Default::default(),
                ).await.unwrap();
                state.changes.caches.insert(contract.clone(), cache);
                let mut storage = LegacyStorage::default();
                let mut loaded = storage.value(contract.clone(), key.clone(), Some(initial), true, &mut heap);
                if overwrite {
                    let replacement = OwnedValue::Object(vec![7u64.into()]);
                    state.changes.caches.get_mut(&contract).unwrap().storage.insert(
                        key.clone(), Some((VersionedState::Updated(7), Some(replacement.clone()))),
                    );
                    storage.replace(contract.clone(), key.clone(), Some(replacement), &mut heap);
                }
                if delete {
                    state.changes.caches.get_mut(&contract).unwrap().storage.insert(
                        key.clone(), Some((VersionedState::Updated(7), None)),
                    );
                    storage.replace(contract.clone(), key.clone(), None, &mut heap);
                    assert!(storage.get(&contract, &key).unwrap().is_none());
                }
                *loaded.as_vec().unwrap()[0].as_mut(&mut heap) = RuntimeValue::from(PrimitiveInteger::U64(99));
                loaded.as_mut_vec().unwrap().push(heap.insert(RuntimeValue::from(PrimitiveInteger::U64(8))));
                assert_eq!(storage.values.len(), 1, "unaccessed entries must not be imported");
                let originals = storage.finish(&heap, &mut state).unwrap();
                if !success { state.changes.caches = originals; }
                let exported = &state.changes.caches[&contract].storage[&key];
                let expected = if success && overwrite { 7u64 } else { 99u64 };
                let version = if success && (overwrite || delete) { VersionedState::Updated(7) } else { VersionedState::FetchedAt(7) };
                let value = if success && delete { None } else { Some(OwnedValue::Object(vec![expected.into()])) };
                assert_eq!(*exported, Some((version, value)));
                if !success {
                    assert_eq!(state.changes.caches[&contract].storage.len(), 1, "rollback must return only accessed original entries");
                }
                drop(loaded);
                let changes = state.changes;
                drop(heap);
                if success {
                    mock.merge_contract_changes(changes, Default::default()).await.unwrap();
                } else {
                    mock.merge_contract_storage(changes.caches).await.unwrap();
                }
                assert_eq!(mock.contract_caches[&contract].storage[&8u64.into()], Some((VersionedState::New, Some(77u64.into()))));
            }
        }
    }

    #[tokio::test]
    async fn cancellation_discards_only_execution_references() {
        let mut mock = MockChainState::with(BlockVersion::V5);
        let contract = Hash::zero();
        mock.internal_set_contract_module(contract.clone(), ContractModule {
            module: Arc::new(Module::new()), version: ContractVersion::V0,
        });
        // SAFETY: the state and every runtime handle are confined to this scope.
        let mut heap = unsafe { Heap::new() };
        let (_, state) = mock.get_contract_environment_for(
            Cow::Borrowed(&contract), None, ContractCaller::System, Default::default(),
        ).await.unwrap();
        let mut storage = LegacyStorage::default();
        storage.value(contract.clone(), 1u64.into(), Some(OwnedValue::Object(vec![1u64.into()])), false, &mut heap);
        // Cancellation drops retained references without exporting them.
        drop(storage);
        assert!(state.changes.caches.is_empty());
    }
}
