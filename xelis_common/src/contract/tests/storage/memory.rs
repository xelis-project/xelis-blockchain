use super::*;

#[tokio::test]
async fn test_memory_storage_local_is_temporary_and_shared_persists_between_invocations() {
    let code = r#"
        entry write() {
            let local = MemoryStorage::new(false);
            let shared = MemoryStorage::new(true);

            require(local.store(b"key", 1) == null, "local first store should return null");
            require(shared.store(b"key", 10) == null, "shared first store should return null");
            require(local.store(b"key", 2).expect("local previous") == 1, "local overwrite should return previous");
            require(shared.store(b"key", 20).expect("shared previous") == 10, "shared overwrite should return previous");
            require(local.load(b"key").expect("local value") == 2, "bad local value");
            require(shared.load(b"key").expect("shared value") == 20, "bad shared value");

            return 0
        }

        entry verify_next_invocation() {
            let local = MemoryStorage::new(false);
            let shared = MemoryStorage::new(true);

            require(!local.has(b"key"), "local memory should not persist");
            require(local.load(b"key") == null, "local memory should load null");
            require(shared.has(b"key"), "shared memory should persist");
            require(shared.load(b"key").expect("shared value") == 20, "shared memory bad value");
            require(shared.delete(b"key").expect("deleted shared") == 20, "shared delete should return value");
            require(!shared.has(b"key"), "shared memory should be deleted");

            return 0
        }

        entry verify_deleted() {
            let shared = MemoryStorage::new(true);
            require(!shared.has(b"key"), "shared memory deletion should persist");
            require(shared.load(b"key") == null, "deleted shared memory should load null");
            return 0
        }
    "#;

    let mut chain_state = MockChainState::with(BlockVersion::V6);
    let contract_hash = deploy_contract(&mut chain_state, code, ContractVersion::V1)
        .await
        .expect("deploy contract")
        .0;

    let write = invoke_contract(
        &mut chain_state,
        &contract_hash,
        InvokeContract::Entry(0),
        vec![],
    )
    .await
    .expect("write memory");
    assert!(write.is_success(), "memory write should succeed: {:?}", write);

    let verify = invoke_contract(
        &mut chain_state,
        &contract_hash,
        InvokeContract::Entry(1),
        vec![],
    )
    .await
    .expect("verify memory");
    assert!(verify.is_success(), "memory verify should succeed: {:?}", verify);

    let deleted = invoke_contract(
        &mut chain_state,
        &contract_hash,
        InvokeContract::Entry(2),
        vec![],
    )
    .await
    .expect("verify deleted memory");
    assert!(deleted.is_success(), "memory delete should persist: {:?}", deleted);
}

#[tokio::test]
async fn test_memory_storage_isolated_per_contract() {
    let writer_code = r#"
        entry write() {
            let shared = MemoryStorage::new(true);
            shared.store(b"key", 55);
            return 0
        }
    "#;
    let other_code = r#"
        entry verify_empty() {
            let shared = MemoryStorage::new(true);
            require(!shared.has(b"key"), "shared memory should be scoped per contract");
            require(shared.load(b"key") == null, "other contract should not see shared memory");
            return 0
        }
    "#;

    let mut chain_state = MockChainState::with(BlockVersion::V6);
    let writer = deploy_contract(&mut chain_state, writer_code, ContractVersion::V1)
        .await
        .expect("deploy writer")
        .0;
    let other = deploy_contract(&mut chain_state, other_code, ContractVersion::V1)
        .await
        .expect("deploy other")
        .0;

    let write = invoke_contract(
        &mut chain_state,
        &writer,
        InvokeContract::Entry(0),
        vec![],
    )
    .await
    .expect("write shared memory");
    assert!(write.is_success(), "writer memory should succeed: {:?}", write);

    let verify = invoke_contract(
        &mut chain_state,
        &other,
        InvokeContract::Entry(0),
        vec![],
    )
    .await
    .expect("verify isolated memory");
    assert!(verify.is_success(), "shared memory should be contract scoped: {:?}", verify);
}