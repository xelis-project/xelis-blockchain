use crate::{
    contract::ContractLog,
    crypto::{KeyPair, PublicKey},
    transaction::mock::MockAccount,
};

use super::*;

fn add_zero_xelis_account(chain_state: &mut MockChainState) -> PublicKey {
    let keypair = KeyPair::new();
    let source = keypair.get_public_key().compress();
    chain_state.accounts.insert(source.clone(), MockAccount {
        balances: [(XELIS_ASSET, keypair.get_public_key().encrypt(0u64))].into_iter().collect(),
        nonce: 0,
    });
    source
}

#[tokio::test]
async fn contract_event_flow() {
    // Create a contract that emits an event when called
    // Another contract that register an event listener from previous one
    // Call the first contract and verify the event is captured & well processed

    let code = r#"
        entry call_event() {
            emit_event(42, ["hello", "world!"]);
            return 0
        }
    "#;

    let mut chain_state = MockChainState::new();
    let emitter_hash = create_contract(&mut chain_state, code, ContractVersion::V1).expect("create emit event contract");

    let code = r#"
        fn on_contract_event(a: string, b: string) -> u64 {
            assert(a == "hello");
            assert(b == "world!");
            println(a + " " + b + " !");
            return 0
        }

        entry register() -> u64 {
            let contract_hash = Hash::from_hex("CONTRACT_HASH");
            let contract = Contract::new(contract_hash).expect("load contract");
            contract.listen_event(42, on_contract_event, 500);
            
            return 0
        }
    "#.replace("CONTRACT_HASH", &emitter_hash.to_string());

    // Create the listener contract and register the callback from an account-backed execution.
    let listener_hash = create_contract(&mut chain_state, &code, ContractVersion::V1)
        .expect("create listener contract");
    let source = add_zero_xelis_account(&mut chain_state);
    let execution = vm::invoke_contract(
        ContractCaller::Impersonate(Cow::Owned(source)),
        &mut chain_state,
        Cow::Owned(listener_hash),
        None,
        std::iter::empty(),
        IndexMap::new(),
        100000,
        InvokeContract::Entry(1),
        Cow::Owned(Default::default()),
        true,
    ).await.expect("register listener contract");

    assert!(execution.is_success(), "listener registration failed {:?}", execution);

    // Invoke the emitter contract to trigger the event
    let execution = invoke_contract(
        &mut chain_state,
        &emitter_hash,
        InvokeContract::Entry(0),
        vec![],
    ).await.expect("invoke emitter contract");

    assert!(execution.is_success(), "emitter contract execution failed {:?}", execution);

    let mut executions = 0;
    for (_, logs) in chain_state.contract_logs {
        for log in logs {
            match log {
                ContractLog::ExitCode(Some(0)) => {
                    executions += 1;
                },
                _ => {},
            }
        }
    }

    // - listener registration execution
    // - call_event execution
    // - on_contract_event execution
    assert_eq!(executions, 3);
}

// get_contract_caller() must return null when the contract is invoked directly
#[tokio::test]
async fn get_contract_caller_is_null_for_direct_invocation() {
    let code = r#"
        entry main() -> u64 {
            let caller: optional<Hash> = get_contract_caller();
            require(caller == null, "expected no contract caller for direct invocation");
            return 0
        }
    "#;

    let mut chain_state = MockChainState::new();
    let contract = create_contract(&mut chain_state, code, ContractVersion::V1)
        .expect("create contract");

    let result = invoke_contract(&mut chain_state, &contract, InvokeContract::Entry(0), vec![])
        .await
        .expect("invoke contract");

    assert!(result.is_success(), "expected success: {:?}", result);
}

#[tokio::test]
async fn listen_event_rejects_zero_max_gas() {
    let emitter_code = r#"
        entry emit() -> u64 {
            emit_event(7, []);
            return 0
        }
    "#;

    let mut chain_state = MockChainState::new();
    let emitter = create_contract(&mut chain_state, emitter_code, ContractVersion::V1)
        .expect("create emitter");

    let listener_code = r#"
        fn on_event() -> u64 {
            return 0
        }

        entry register() -> u64 {
            let emitter: Hash = Hash::from_hex("EMITTER_HASH");
            let contract = Contract::new(emitter).expect("load emitter");
            contract.listen_event(7, on_event, 0u64);
            return 0
        }
    "#.replace("EMITTER_HASH", &emitter.to_string());

    let listener = create_contract(&mut chain_state, &listener_code, ContractVersion::V1)
        .expect("create listener");
    let source = add_zero_xelis_account(&mut chain_state);

    let result = vm::invoke_contract(
        ContractCaller::Impersonate(Cow::Owned(source)),
        &mut chain_state,
        Cow::Owned(listener),
        None,
        std::iter::empty(),
        IndexMap::new(),
        100000,
        InvokeContract::Entry(1),
        Cow::Owned(Default::default()),
        true,
    ).await.expect("register zero gas listener");
    assert!(!result.is_success(), "zero-gas listener registration must fail: {:?}", result);
    assert!(
        chain_state.events_listeners.is_empty(),
        "zero-gas listener registration must not be committed"
    );
}

// get_contract_caller() must return the emitting contract's hash when called
// from inside an event callback not the TX/system hash.
#[tokio::test]
async fn get_contract_caller_returns_emitter_in_event_callback() {
    let emitter_code = r#"
        entry emit() -> u64 {
            emit_event(7, []);
            return 0
        }
    "#;

    let mut chain_state = MockChainState::new();
    let emitter = create_contract(&mut chain_state, emitter_code, ContractVersion::V1)
        .expect("create emitter");

    // The listener asserts that get_contract_caller() returns the emitter hash.
    let listener_code = r#"
        fn on_event() -> u64 {
            let caller: optional<Hash> = get_contract_caller();
            require(caller != null, "expected emitter as caller got null");
            let expected: Hash = Hash::from_hex("EMITTER_HASH");
            require(caller.unwrap() == expected, "wrong emitter hash returned by get contract caller");
            return 0
        }

        entry register() -> u64 {
            let emitter: Hash = Hash::from_hex("EMITTER_HASH");
            let contract = Contract::new(emitter).expect("load emitter");
            contract.listen_event(7, on_event, 10000);
            return 0
        }
    "#.replace("EMITTER_HASH", &emitter.to_string());

    let listener = create_contract(&mut chain_state, &listener_code, ContractVersion::V1)
        .expect("create listener");
    let source = add_zero_xelis_account(&mut chain_state);
    let register = vm::invoke_contract(
        ContractCaller::Impersonate(Cow::Owned(source)),
        &mut chain_state,
        Cow::Owned(listener),
        None,
        std::iter::empty(),
        IndexMap::new(),
        100000,
        InvokeContract::Entry(1),
        Cow::Owned(Default::default()),
        true,
    ).await.expect("register listener");
    assert!(register.is_success(), "listener registration failed: {:?}", register);

    let result = invoke_contract(&mut chain_state, &emitter, InvokeContract::Entry(0), vec![])
        .await
        .expect("invoke emitter");
    assert!(result.is_success(), "emitter failed: {:?}", result);

    // Find the callback's ExitCode log to confirm it ran and succeeded.
    let callback_success = chain_state.contract_logs.values()
        .flat_map(|logs| logs.iter())
        .filter(|log| matches!(log, ContractLog::ExitCode(Some(0))))
        .count();

    // register() + emit() + on_event() = 3 successful exits
    assert_eq!(callback_success, 3, "event callback did not run or failed");
}

// get_contract_caller() must return the calling contract's hash when invoked
// via contract.call() (inter-contract call).
#[tokio::test]
async fn get_contract_caller_returns_caller_in_inter_contract_call() {
    let code_b = r#"
        pub fn check_caller(expected_caller: Hash) -> u64 {
            let caller: optional<Hash> = get_contract_caller();
            require(caller != null, "expected a contract caller got null");
            require(caller.unwrap() == expected_caller, "wrong contract caller hash");
            return 0
        }
    "#;

    let mut chain_state = MockChainState::new();
    let hash_b = create_contract(&mut chain_state, code_b, ContractVersion::V1)
        .expect("create contract B");

    // Contract A: entry calls B (chunk 0) passing A's own hash for B to verify.
    let code_a = r#"
        entry run() {
            let b_hash: Hash = Hash::from_hex("EMITTER_HASH");
            let b = Contract::new(b_hash).expect("load contract B");
            let a_hash: Hash = get_contract_hash();
            let deposits: map<Hash, u64> = {};
            let res: u64 = b.call(0u16, [a_hash], deposits);
            require(res == 0, "contract B call failed");

            return 0;
        }
    "#.replace("EMITTER_HASH", &hash_b.to_string());

    let hash_a = create_contract(&mut chain_state, &code_a, ContractVersion::V1)
        .expect("create contract A");

    let result = invoke_contract_with_permission(
        &mut chain_state,
        &hash_a,
        InvokeContract::Entry(0),
        vec![],
        InterContractPermission::All,
    )
        .await
        .expect("invoke contract A");

    assert!(result.is_success(), "contract A invocation failed: {:?}", result);
}