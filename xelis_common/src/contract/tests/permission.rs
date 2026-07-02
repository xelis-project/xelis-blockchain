use indexmap::IndexSet;
use crate::contract::{ContractCall, ContractCallChunk};
use super::*;

// One public chunk (chunk 0)
const B_ONE_CHUNK: &str = r#"
    pub fn noop() -> u64 {
        return 0
    }
"#;

// Two public chunks (chunk 0 and chunk 1)
const B_TWO_CHUNKS: &str = r#"
    pub fn noop0() -> u64 {
        return 0
    }
    pub fn noop1() -> u64 {
        return 0
    }
"#;

// One public chunk (0) followed by one private chunk (1)
const B_PUBLIC_AND_PRIVATE: &str = r#"
    pub fn public_fn() -> u64 {
        return 0
    }
    fn private_fn() -> u64 {
        return 0
    }
"#;

/// Contract that calls `chunk` of `target` via `call()`
fn code_calling(target: &str, chunk: u16) -> String {
    format!(r#"
        entry run() {{
            let target: Hash = Hash::from_hex("{target}");
            let b = Contract::new(target).expect("load");
            let deposits: map<Hash, u64> = {{}};
            let res: u64 = b.call({chunk}u16, [], deposits);
            return 0
        }}
    "#)
}

/// Contract that calls `chunk` of `target` via `delegate()` (no permission check)
fn code_delegating(target: &str, chunk: u16) -> String {
    format!(r#"
        entry run() {{
            let target: Hash = Hash::from_hex("{target}");
            let b = Contract::new(target).expect("load");
            let res: u64 = b.delegate({chunk}u16, []);
            return 0
        }}
    "#)
}

fn specific(contract: &Hash, chunk: ContractCallChunk) -> InterContractPermission {
    let mut set = IndexSet::new();
    set.insert(ContractCall { contract: contract.clone(), chunk });
    InterContractPermission::Specific(set)
}

fn exclude(contract: &Hash, chunk: ContractCallChunk) -> InterContractPermission {
    let mut set = IndexSet::new();
    set.insert(ContractCall { contract: contract.clone(), chunk });
    InterContractPermission::Exclude(set)
}

// Permission::None (the default) prevents any inter-contract calls
#[tokio::test]
async fn permission_none_blocks_call() {
    let mut state = MockChainState::new();
    let b = create_contract(&mut state, B_ONE_CHUNK, ContractVersion::V1).expect("create contract B");
    let a = create_contract(&mut state, &code_calling(&b.to_string(), 0), ContractVersion::V1).expect("create contract A");

    let res = invoke_contract_with_permission(
        &mut state,
        &a,
        InvokeContract::Entry(0),
        vec![],
        InterContractPermission::None,
    ).await.expect("invoke contract");

    assert!(!res.is_success(), "None permission should block inter-contract call: {:?}", res);
}

// Permission::All allows calling any contract.
#[tokio::test]
async fn permission_all_allows_any_call() {
    let mut state = MockChainState::new();
    let b = create_contract(&mut state, B_ONE_CHUNK, ContractVersion::V1).expect("create contract B");
    let a = create_contract(&mut state, &code_calling(&b.to_string(), 0), ContractVersion::V1).expect("create contract A");

    let res = invoke_contract_with_permission(
        &mut state,
        &a,
        InvokeContract::Entry(0),
        vec![],
        InterContractPermission::All,
    ).await.expect("invoke contract");

    assert!(res.is_success(), "All permission should allow any call: {:?}", res);
}

// Permission::Specific with ContractCallChunk::All allows calling the listed contract.
#[tokio::test]
async fn permission_specific_allows_listed_contract() {
    let mut state = MockChainState::new();
    let b = create_contract(&mut state, B_ONE_CHUNK, ContractVersion::V1).expect("create contract B");
    let a = create_contract(&mut state, &code_calling(&b.to_string(), 0), ContractVersion::V1).expect("create contract A");

    let res = invoke_contract_with_permission(
        &mut state, &a, InvokeContract::Entry(0), vec![],
        specific(&b, ContractCallChunk::All),
    ).await.expect("invoke contract");

    assert!(res.is_success(), "Specific(B, All) should allow calling B: {:?}", res);
}

// Permission::Specific blocks contracts not in the allowed set.
#[tokio::test]
async fn permission_specific_blocks_unlisted_contract() {
    let mut state = MockChainState::new();
    let b = create_contract(&mut state, B_ONE_CHUNK, ContractVersion::V1).expect("create contract B");
    let c = create_contract(&mut state, B_ONE_CHUNK, ContractVersion::V1).expect("create contract C");
    // A is only allowed to call B, but its code tries to call C.
    let a = create_contract(&mut state, &code_calling(&c.to_string(), 0), ContractVersion::V1).expect("create contract A");

    let res = invoke_contract_with_permission(
        &mut state,
        &a,
        InvokeContract::Entry(0),
        vec![],
        specific(&b, ContractCallChunk::All),
    ).await.expect("invoke contract");

    assert!(!res.is_success(), "Specific(B) should block calling unlisted C: {:?}", res);
}

// Permission::Specific with ContractCallChunk::Specific allows the exact listed chunk.
#[tokio::test]
async fn permission_specific_chunk_allows_listed_chunk() {
    let mut state = MockChainState::new();
    let b = create_contract(&mut state, B_TWO_CHUNKS, ContractVersion::V1).expect("create contract B");
    let a = create_contract(&mut state, &code_calling(&b.to_string(), 0), ContractVersion::V1).expect("create contract A");

    let mut chunks = IndexSet::new();
    chunks.insert(0u16);
    let res = invoke_contract_with_permission(
        &mut state,
        &a,
        InvokeContract::Entry(0),
        vec![],
        specific(&b, ContractCallChunk::Specific(chunks)),
    ).await.expect("invoke contract");

    assert!(res.is_success(), "Specific chunk [0] should allow calling chunk 0: {:?}", res);
}

// Permission::Specific with ContractCallChunk::Specific blocks chunks not in the set.
#[tokio::test]
async fn permission_specific_chunk_blocks_unlisted_chunk() {
    let mut state = MockChainState::new();
    let b = create_contract(&mut state, B_TWO_CHUNKS, ContractVersion::V1).expect("create contract B");
    // A tries to call chunk 1, but only chunk 0 is permitted.
    let a = create_contract(&mut state, &code_calling(&b.to_string(), 1), ContractVersion::V1).expect("create contract A");

    let mut chunks = IndexSet::new();
    chunks.insert(0u16);
    let res = invoke_contract_with_permission(
        &mut state,
        &a,
        InvokeContract::Entry(0),
        vec![],
        specific(&b, ContractCallChunk::Specific(chunks)),
    ).await.expect("invoke contract");

    assert!(!res.is_success(), "Specific chunk [0] should block calling chunk 1: {:?}", res);
}

// Permission::Specific with ContractCallChunk::Exclude blocks the excluded chunk.
#[tokio::test]
async fn permission_specific_chunk_exclude_blocks_excluded_chunk() {
    let mut state = MockChainState::new();
    let b = create_contract(&mut state, B_TWO_CHUNKS, ContractVersion::V1).unwrap();
    // Chunk 0 is excluded → calling it must fail.
    let a = create_contract(&mut state, &code_calling(&b.to_string(), 0), ContractVersion::V1).unwrap();

    let mut excluded = IndexSet::new();
    excluded.insert(0u16);
    let res = invoke_contract_with_permission(
        &mut state, &a, InvokeContract::Entry(0), vec![],
        specific(&b, ContractCallChunk::Exclude(excluded)),
    ).await.expect("invoke contract");

    assert!(!res.is_success(), "Exclude(chunk 0) should block calling chunk 0: {:?}", res);
}

// Permission::Specific with ContractCallChunk::Exclude allows chunks not in the excluded set.
#[tokio::test]
async fn permission_specific_chunk_exclude_allows_non_excluded_chunk() {
    let mut state = MockChainState::new();
    let b = create_contract(&mut state, B_TWO_CHUNKS, ContractVersion::V1).unwrap();
    // Chunk 0 is excluded; calling chunk 1 must succeed.
    let a = create_contract(&mut state, &code_calling(&b.to_string(), 1), ContractVersion::V1).unwrap();

    let mut excluded = IndexSet::new();
    excluded.insert(0u16);
    let res = invoke_contract_with_permission(
        &mut state, &a, InvokeContract::Entry(0), vec![],
        specific(&b, ContractCallChunk::Exclude(excluded)),
    ).await.expect("invoke contract");

    assert!(res.is_success(), "Exclude(chunk 0) should allow calling chunk 1: {:?}", res);
}

// Permission::Exclude blocks the listed contract entirely (ContractCallChunk::All).
#[tokio::test]
async fn permission_exclude_blocks_excluded_contract() {
    let mut state = MockChainState::new();
    let b = create_contract(&mut state, B_ONE_CHUNK, ContractVersion::V1).unwrap();
    let a = create_contract(&mut state, &code_calling(&b.to_string(), 0), ContractVersion::V1).unwrap();

    let res = invoke_contract_with_permission(
        &mut state,
        &a,
        InvokeContract::Entry(0),
        vec![],
        exclude(&b, ContractCallChunk::All),
    ).await.expect("invoke contract");

    assert!(!res.is_success(), "Exclude(B) should block calling B: {:?}", res);
}

// Permission::Exclude allows calls to contracts not in the exclusion set
#[tokio::test]
async fn permission_exclude_allows_non_excluded_contract() {
    let mut state = MockChainState::new();
    let b = create_contract(&mut state, B_ONE_CHUNK, ContractVersion::V1).unwrap();
    let c = create_contract(&mut state, B_ONE_CHUNK, ContractVersion::V1).unwrap();
    // A excludes B; it tries to call C which is not excluded.
    let a = create_contract(&mut state, &code_calling(&c.to_string(), 0), ContractVersion::V1).unwrap();

    let res = invoke_contract_with_permission(
        &mut state, &a, InvokeContract::Entry(0), vec![],
        exclude(&b, ContractCallChunk::All),
    ).await.unwrap();

    assert!(res.is_success(), "Exclude(B) should allow calling non-excluded C: {:?}", res);
}

// `delegate` bypasses InterContractPermission (works even with Permission::None)
#[tokio::test]
async fn delegate_bypasses_permission_check() {
    let mut state = MockChainState::new();
    let b = create_contract(&mut state, B_ONE_CHUNK, ContractVersion::V1).expect("create contract B");
    let a = create_contract(&mut state, &code_delegating(&b.to_string(), 0), ContractVersion::V1).expect("create contract A");

    let res = invoke_contract_with_permission(
        &mut state,
        &a,
        InvokeContract::Entry(0),
        vec![],
        InterContractPermission::None,
    ).await.expect("invoke delegating contract");

    assert!(res.is_success(), "delegate should bypass permission even with None: {:?}", res);
}

// Calling a private (non-`pub fn`) chunk via `call()` is rejected, regardless of permission
#[tokio::test]
async fn private_chunk_cannot_be_called_via_call() {
    let mut state = MockChainState::new();
    let b = create_contract(&mut state, B_PUBLIC_AND_PRIVATE, ContractVersion::V1).expect("create contract B");
    let a = create_contract(&mut state, &code_calling(&b.to_string(), 1), ContractVersion::V1).expect("create contract A");

    let res = invoke_contract_with_permission(
        &mut state,
        &a,
        InvokeContract::Entry(0),
        vec![],
        InterContractPermission::All,
    ).await.expect("invoke contract");

    assert!(!res.is_success(), "calling a private chunk should fail even with All permission: {:?}", res);
}


// `delegate` keeps the current environment, so target bytecode must use the same contract version.
#[tokio::test]
async fn delegate_rejects_version_mismatch() {
    let mut state = MockChainState::new();
    let b = create_contract(&mut state, B_ONE_CHUNK, ContractVersion::V0).expect("create contract B");
    let a = create_contract(&mut state, &code_delegating(&b.to_string(), 0), ContractVersion::V1).expect("create contract A");

    let res = invoke_contract_with_permission(
        &mut state,
        &a,
        InvokeContract::Entry(0),
        vec![],
        InterContractPermission::All,
    ).await.expect("invoke delegating contract");

    assert!(!res.is_success(), "delegate should reject version mismatches: {:?}", res);
}
