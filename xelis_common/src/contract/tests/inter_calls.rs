use indexmap::IndexSet;
use crate::contract::{ContractCall, ContractCallChunk, ExitError, InterContractPermission, vm::ExitValue};
use super::*;

/// Asserts that the execution result carries a `RuntimeError` whose message
/// contains `expected_fragment`.
#[track_caller]
fn assert_runtime_error(res: &vm::ExecutionResult, expected_fragment: &str) {
    match &res.exit_value {
        ExitValue::Error(ExitError::RuntimeError(msg)) => {
            assert!(
                msg.contains(expected_fragment),
                "expected RuntimeError containing {:?}, got message {:?}",
                expected_fragment,
                msg,
            );
        }
        other => panic!(
            "expected ExitValue::Error(ExitError::RuntimeError(...{}...)), got {:?}",
            expected_fragment, other
        ),
    }
}

/// Leaf contract with one no-arg public chunk.
const LEAF_NOOP: &str = r#"
    pub fn noop() -> u64 {
        return 0
    }
"#;

/// Leaf contract with one public chunk accepting a single u64.
const LEAF_ACCEPTS_U64: &str = r#"
    pub fn accepts_u64(x: u64) -> u64 {
        return x
    }
"#;

/// Builds a "middle" contract whose only public entry calls chunk 0 of
/// `target` and forwards the return value.  Used for A → B → C chains.
fn code_middle(target: &Hash) -> String {
    format!(
        r#"
        pub fn relay() -> u64 {{
            let t: Hash = Hash::from_hex("{target}");
            let c = Contract::new(t).expect("load C");
            let deposits: map<Hash, u64> = {{}};
            let res: u64 = c.call(0u16, [], deposits);
            return res
        }}
    "#
    )
}

/// Top-level entry that calls chunk 0 of `target` (no params, no deposits).
fn code_top_calling(target: &Hash) -> String {
    format!(
        r#"
        entry run() {{
            let t: Hash = Hash::from_hex("{target}");
            let b = Contract::new(t).expect("load");
            let deposits: map<Hash, u64> = {{}};
            let res: u64 = b.call(0u16, [], deposits);
            return 0
        }}
    "#
    )
}

/// Top-level entry that calls chunk 0 of `target` with a single u64 param.
fn code_top_calling_with_u64(target: &Hash, value: u64) -> String {
    format!(
        r#"
        entry run() {{
            let t: Hash = Hash::from_hex("{target}");
            let b = Contract::new(t).expect("load");
            let deposits: map<Hash, u64> = {{}};
            let res: u64 = b.call(0u16, [{value}u64], deposits);
            return 0
        }}
    "#
    )
}

/// Top-level entry that calls chunk 0 of `target` with NO params even though
/// the callee expects one u64 (triggers parameter-count mismatch).
fn code_top_calling_missing_param(target: &Hash) -> String {
    format!(
        r#"
        entry run() {{
            let t: Hash = Hash::from_hex("{target}");
            let b = Contract::new(t).expect("load");
            let deposits: map<Hash, u64> = {{}};
            let res: u64 = b.call(0u16, [], deposits);
            return 0
        }}
    "#
    )
}

/// Top-level entry that calls chunk 0 of `target` with TOO MANY params even
/// though the callee expects none (triggers parameter-count mismatch).
fn code_top_calling_extra_param(target: &Hash) -> String {
    format!(
        r#"
        entry run() {{
            let t: Hash = Hash::from_hex("{target}");
            let b = Contract::new(t).expect("load");
            let deposits: map<Hash, u64> = {{}};
            let res: u64 = b.call(0u16, [42u64], deposits);
            return 0
        }}
    "#
    )
}

/// Top-level entry that tries `Contract::new` on a hash not registered in the
/// state and handles the resulting `null` gracefully (returns 0 = success).
fn code_top_null_contract(unknown: &Hash) -> String {
    format!(
        r#"
        entry run() {{
            let t: Hash = Hash::from_hex("{unknown}");
            let maybe = Contract::new(t);
            if maybe.is_none() {{
                return 0
            }}
            return 1
        }}
    "#
    )
}

fn allow_specific(contract: &Hash) -> InterContractPermission {
    let mut set = IndexSet::new();
    set.insert(ContractCall {
        contract: contract.clone(),
        chunk: ContractCallChunk::All,
    });
    InterContractPermission::Specific(set)
}

fn allow_specific_two(a: &Hash, b: &Hash) -> InterContractPermission {
    let mut set = IndexSet::new();
    set.insert(ContractCall {
        contract: a.clone(),
        chunk: ContractCallChunk::All,
    });
    set.insert(ContractCall {
        contract: b.clone(),
        chunk: ContractCallChunk::All,
    });
    InterContractPermission::Specific(set)
}

/// A → B → C (two hops) all succeed when permission is `All`.
#[tokio::test]
async fn chained_call_a_b_c_succeeds_with_all_permission() {
    let mut state = MockChainState::new();

    // C: leaf
    let c = create_contract(&mut state, LEAF_NOOP, ContractVersion::V1).expect("create C");
    // B: relays to C
    let b = create_contract(&mut state, &code_middle(&c), ContractVersion::V1).expect("create B");
    // A: calls B's relay chunk
    let a = create_contract(&mut state, &code_top_calling(&b), ContractVersion::V1).expect("create A");

    let res = invoke_contract_with_permission(
        &mut state,
        &a,
        InvokeContract::Entry(0),
        vec![],
        InterContractPermission::All,
    )
    .await
    .expect("invoke A");

    assert!(res.is_success(), "A→B→C chain should succeed with All permission: {:?}", res);
}

/// A → B → C: permission `Specific({B})` is set when A is invoked.
/// B then tries to call C which is not in the allowed set → whole chain fails.
#[tokio::test]
async fn chained_call_b_to_c_blocked_by_a_permission() {
    let mut state = MockChainState::new();

    let c = create_contract(&mut state, LEAF_NOOP, ContractVersion::V1).expect("create C");
    let b = create_contract(&mut state, &code_middle(&c), ContractVersion::V1).expect("create B");
    let a = create_contract(&mut state, &code_top_calling(&b), ContractVersion::V1).expect("create A");

    // Only B is allowed; C is not in the set, so B→C should be denied.
    let res = invoke_contract_with_permission(
        &mut state,
        &a,
        InvokeContract::Entry(0),
        vec![],
        allow_specific(&b),
    )
    .await
    .expect("invoke A");

    assert!(!res.is_success(), "B→C should be blocked when only B is allowed: {:?}", res);
    assert_runtime_error(&res, "Permission denied to call this contract");
}

/// A → B → C: permission `Specific({B, C})` allows both hops → succeeds.
#[tokio::test]
async fn chained_call_b_to_c_allowed_when_both_in_specific() {
    let mut state = MockChainState::new();

    let c = create_contract(&mut state, LEAF_NOOP, ContractVersion::V1).expect("create C");
    let b = create_contract(&mut state, &code_middle(&c), ContractVersion::V1).expect("create B");
    let a = create_contract(&mut state, &code_top_calling(&b), ContractVersion::V1).expect("create A");

    let res = invoke_contract_with_permission(
        &mut state,
        &a,
        InvokeContract::Entry(0),
        vec![],
        allow_specific_two(&b, &c),
    )
    .await
    .expect("invoke A");

    assert!(res.is_success(), "A→B→C should succeed when both B and C are in Specific: {:?}", res);
}

/// `Permission::None` blocks the very first inter-contract call (A→B) so no
/// chaining is possible at all.
#[tokio::test]
async fn chained_call_blocked_at_first_hop_with_none_permission() {
    let mut state = MockChainState::new();

    let c = create_contract(&mut state, LEAF_NOOP, ContractVersion::V1).expect("create C");
    let b = create_contract(&mut state, &code_middle(&c), ContractVersion::V1).expect("create B");
    let a = create_contract(&mut state, &code_top_calling(&b), ContractVersion::V1).expect("create A");

    let res = invoke_contract_with_permission(
        &mut state,
        &a,
        InvokeContract::Entry(0),
        vec![],
        InterContractPermission::None,
    )
    .await
    .expect("invoke A");

    assert!(!res.is_success(), "None permission must block first hop A→B: {:?}", res);
    assert_runtime_error(&res, "Permission denied to call this contract");
}

/// Calling a chunk that expects zero params with extra params must fail.
#[tokio::test]
async fn call_with_extra_params_fails() {
    let mut state = MockChainState::new();

    // B expects NO parameters
    let b = create_contract(&mut state, LEAF_NOOP, ContractVersion::V1).expect("create B");
    // A passes one extra u64
    let a = create_contract(&mut state, &code_top_calling_extra_param(&b), ContractVersion::V1)
        .expect("create A");

    let res = invoke_contract_with_permission(
        &mut state,
        &a,
        InvokeContract::Entry(0),
        vec![],
        InterContractPermission::All,
    )
    .await
    .expect("invoke A");

    assert!(!res.is_success(), "passing extra params to a no-param chunk must fail: {:?}", res);
    assert_runtime_error(&res, "Invalid parameters for contract call");
}

/// Calling a chunk that expects one u64 with no params must fail.
#[tokio::test]
async fn call_with_missing_param_fails() {
    let mut state = MockChainState::new();

    // B expects one u64
    let b = create_contract(&mut state, LEAF_ACCEPTS_U64, ContractVersion::V1).expect("create B");
    // A passes nothing
    let a = create_contract(&mut state, &code_top_calling_missing_param(&b), ContractVersion::V1)
        .expect("create A");

    let res = invoke_contract_with_permission(
        &mut state,
        &a,
        InvokeContract::Entry(0),
        vec![],
        InterContractPermission::All,
    )
    .await
    .expect("invoke A");

    assert!(!res.is_success(), "calling chunk with missing param must fail: {:?}", res);
    assert_runtime_error(&res, "Invalid parameters for contract call");
}

/// Calling a chunk that expects one u64 with the correct param succeeds.
#[tokio::test]
async fn call_with_correct_param_succeeds() {
    let mut state = MockChainState::new();

    let b = create_contract(&mut state, LEAF_ACCEPTS_U64, ContractVersion::V1).expect("create B");
    let a = create_contract(&mut state, &code_top_calling_with_u64(&b, 42), ContractVersion::V1)
        .expect("create A");

    let res = invoke_contract_with_permission(
        &mut state,
        &a,
        InvokeContract::Entry(0),
        vec![],
        InterContractPermission::All,
    )
    .await
    .expect("invoke A");

    assert!(res.is_success(), "calling chunk with correct u64 param must succeed: {:?}", res);
}

/// `Contract::new` on an unregistered hash returns `null`; the caller handles
/// it gracefully and returns exit-code 0.
#[tokio::test]
async fn call_nonexistent_contract_returns_null() {
    let mut state = MockChainState::new();

    // Deterministic hash not registered in state
    let unknown = Hash::new([0xDE; 32]);
    let a = create_contract(&mut state, &code_top_null_contract(&unknown), ContractVersion::V1)
        .expect("create A");

    let res = invoke_contract_with_permission(
        &mut state,
        &a,
        InvokeContract::Entry(0),
        vec![],
        InterContractPermission::All,
    )
    .await
    .expect("invoke A");

    assert!(res.is_success(), "graceful null-contract handling must return success: {:?}", res);
}

/// Calling `.expect()` on `null` (when the contract isn't registered) panics
/// the VM and the execution is marked as failed.
#[tokio::test]
async fn call_nonexistent_contract_expect_fails() {
    let mut state = MockChainState::new();

    let unknown = Hash::new([0xDE; 32]);
    // A calls .expect("load") on the null result → should fail
    let code = format!(
        r#"
        entry run() {{
            let t: Hash = Hash::from_hex("{unknown}");
            let b = Contract::new(t).expect("load");
            let deposits: map<Hash, u64> = {{}};
            let res: u64 = b.call(0u16, [], deposits);
            return 0
        }}
    "#
    );
    let a = create_contract(&mut state, &code, ContractVersion::V1).expect("create A");

    let res = invoke_contract_with_permission(
        &mut state,
        &a,
        InvokeContract::Entry(0),
        vec![],
        InterContractPermission::All,
    )
    .await
    .expect("invoke A");

    assert!(!res.is_success(), "expect() on null contract must fail: {:?}", res);
    assert_runtime_error(&res, "load");
}

/// A calls B which returns a concrete value; A verifies the value and only
/// returns 0 if it matches, so the success of the top-level execution proves
/// that the return value was correctly propagated through the call.
#[tokio::test]
async fn inter_call_return_value_propagated() {
    let b_code = r#"
        pub fn give_42() -> u64 {
            return 42
        }
    "#;

    let mut state = MockChainState::new();
    let b = create_contract(&mut state, b_code, ContractVersion::V1).expect("create B");

    let a_code = format!(
        r#"
        entry run() {{
            let t: Hash = Hash::from_hex("{b}");
            let b_contract = Contract::new(t).expect("load B");
            let deposits: map<Hash, u64> = {{}};
            let val: u64 = b_contract.call(0u16, [], deposits);
            require(val == 42, "expected 42 from B");
            return 0
        }}
    "#
    );
    let a = create_contract(&mut state, &a_code, ContractVersion::V1).expect("create A");

    let res = invoke_contract_with_permission(
        &mut state,
        &a,
        InvokeContract::Entry(0),
        vec![],
        InterContractPermission::All,
    )
    .await
    .expect("invoke A");

    assert!(res.is_success(), "return value from B must equal 42 in A: {:?}", res);
}
