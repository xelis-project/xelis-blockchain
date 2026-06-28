use std::{borrow::Cow, collections::HashMap, sync::Arc};

use curve25519_dalek::Scalar;
use indexmap::IndexMap;

use crate::{
    block::BlockVersion,
    config::{
        COST_PER_SCHEDULED_EXECUTION_AT_BLOCK_END,
        MAX_GAS_USAGE_PER_TX,
        TX_GAS_BURN_PERCENT,
        XELIS_ASSET
    },
    contract::{
        ContractCache,
        ContractLog,
        ContractVersion,
        InterContractPermission,
        Source,
        vm::{self, ContractCaller, InvokeContract, refund_gas_sources},
    },
    crypto::{
        Hash,
        Hashable,
        KeyPair,
        proofs::G
    },
    transaction::{
        Reference,
        ContractDeposit,
        TxVersion,
        builder::{
            FeeBuilder,
            InvokeContractBuilder,
            TransactionBuilder,
            TransactionTypeBuilder
        },
        mock::{
            MockAccount,
            MockChainState,
            TrackedAccount,
            TrackedAccountState
        },
        verify::{BlockchainApplyState, BlockchainContractState}
    },
    versioned::VersionedState
};

use super::create_contract;

fn refund_gas_amount(state: &MockChainState, caller: &Hash) -> u64 {
    state.contract_logs
        .get(caller)
        .into_iter()
        .flat_map(|logs| logs.iter())
        .filter_map(|log| match log {
            ContractLog::RefundGas { amount } => Some(*amount),
            _ => None
        })
        .sum()
}

fn assert_account_xelis_balance(
    state: &MockChainState,
    keypair: &KeyPair,
    source: &crate::crypto::elgamal::CompressedPublicKey,
    expected: u64,
    message: &str,
) {
    let balance = &state.accounts.get(source).unwrap().balances[&XELIS_ASSET];
    assert_eq!(
        keypair.decrypt_to_point(balance),
        Scalar::from(expected) * (*G),
        "{}",
        message
    );
}

fn assert_account_gas_conservation(
    state: &MockChainState,
    keypair: &KeyPair,
    source: &crate::crypto::elgamal::CompressedPublicKey,
    reserved_gas: u64,
    used_gas: u64,
    gas_fee_before: u64,
    burned_fee_before: u64,
) {
    let expected_burned_gas = used_gas * TX_GAS_BURN_PERCENT / 100;
    let expected_fee_gas = used_gas - expected_burned_gas;
    let refunded_gas = reserved_gas - used_gas;
    let gas_fee_delta = state.gas_fee - gas_fee_before;
    let burned_fee_delta = state.burned_fee - burned_fee_before;

    assert_eq!(
        gas_fee_delta,
        expected_fee_gas,
        "miner fee must be charged only from gas actually used"
    );
    assert_eq!(
        burned_fee_delta,
        expected_burned_gas,
        "burned fee must be charged only from gas actually used"
    );

    let balance = &state.accounts.get(source).unwrap().balances[&XELIS_ASSET];
    assert_eq!(
        keypair.decrypt_to_point(balance),
        Scalar::from(refunded_gas) * (*G),
        "payer must receive only unused reserved gas"
    );
    assert_eq!(
        refunded_gas + gas_fee_delta + burned_fee_delta,
        reserved_gas,
        "gas accounting must conserve the reserved input"
    );
}

async fn assert_contract_gas_conservation(
    state: &mut MockChainState,
    contract: &Hash,
    reserved_gas: u64,
    used_gas: u64,
    gas_fee_before: u64,
    burned_fee_before: u64,
) {
    let expected_burned_gas = used_gas * TX_GAS_BURN_PERCENT / 100;
    let expected_fee_gas = used_gas - expected_burned_gas;
    let refunded_gas = reserved_gas - used_gas;
    let gas_fee_delta = state.gas_fee - gas_fee_before;
    let burned_fee_delta = state.burned_fee - burned_fee_before;

    assert_eq!(
        gas_fee_delta,
        expected_fee_gas,
        "miner fee must be charged only from gas actually used"
    );
    assert_eq!(
        burned_fee_delta,
        expected_burned_gas,
        "burned fee must be charged only from gas actually used"
    );

    let (_, balance) = state.get_contract_balance_for_gas(contract).await.unwrap();
    assert_eq!(
        *balance,
        refunded_gas,
        "contract must receive only unused reserved gas"
    );
    assert_eq!(
        refunded_gas + gas_fee_delta + burned_fee_delta,
        reserved_gas,
        "gas accounting must conserve the reserved input"
    );
}

fn assert_gas_injection_log(log: &ContractLog, expected_contract: &Hash, expected_amount: u64) {
    match log {
        ContractLog::GasInjection { contract, amount } => {
            assert_eq!(contract, expected_contract);
            assert_eq!(*amount, expected_amount);
        },
        other => panic!("expected gas injection log, got {:?}", other)
    }
}

#[tokio::test]
async fn test_blockchain_apply_state_gas_tracking() {
    let mut state = MockChainState::new();
    
    // Test gas fee tracking
    state.add_gas_fee(1000).await.unwrap();
    assert_eq!(state.gas_fee, 1000);
    
    state.add_gas_fee(500).await.unwrap();
    assert_eq!(state.gas_fee, 1500);
    
    // Test burned fee tracking
    state.add_burned_fee(250).await.unwrap();
    assert_eq!(state.burned_fee, 250);
    
    // Test burned coins tracking
    state.add_burned_coins(&XELIS_ASSET, 100).await.unwrap();
    assert_eq!(state.burned_coins.get(&XELIS_ASSET), Some(&100));
    
    state.add_burned_coins(&XELIS_ASSET, 50).await.unwrap();
    assert_eq!(state.burned_coins.get(&XELIS_ASSET), Some(&150));
}

#[tokio::test]
async fn test_contract_balance_for_gas() {
    let mut state = MockChainState::new();
    let contract_hash = Hash::zero();
    
    // Get contract balance (should initialize to 0)
    {
        let (versioned_state, balance) = state.get_contract_balance_for_gas(&contract_hash).await.unwrap();
        assert_eq!(*balance, 0);
        assert_eq!(*versioned_state, VersionedState::New);
        
        // Update the balance
        *balance = 5000;
        // New state doesn't change when marked as updated
        versioned_state.mark_updated();
        assert_eq!(*versioned_state, VersionedState::New); // Still new
    }
    
    // Verify the update persisted in the state
    {
        let (versioned_state, balance) = state.get_contract_balance_for_gas(&contract_hash).await.unwrap();
        assert_eq!(*balance, 5000);
        // The state is still the same object, so it's still New
        assert_eq!(*versioned_state, VersionedState::New);
    }
    
    // Simulate fetching from storage
    {
        let cache = state.contract_caches.get_mut(&contract_hash).unwrap();
        let (versioned_state, _) = cache.balances.get_mut(&XELIS_ASSET)
            .unwrap()
            .as_mut()
            .unwrap();
        *versioned_state = VersionedState::FetchedAt(10);
    }
    
    // Now mark it as updated
    {
        let (versioned_state, balance) = state.get_contract_balance_for_gas(&contract_hash).await.unwrap();
        assert_eq!(*versioned_state, VersionedState::FetchedAt(10));
        *balance = 6000;
        versioned_state.mark_updated();
        assert_eq!(*versioned_state, VersionedState::Updated(10));
    }
}

#[tokio::test]
async fn increase_gas_limit_pre_invoke_check_includes_requested_amount() {
    let code = r#"
        entry main() {
            require(!increase_gas_limit(2u64), "current deposit must not fund gas injection pre-check");
            return 0
        }
    "#;

    let mut chain_state = MockChainState::new();
    let contract = create_contract(&mut chain_state, code, ContractVersion::V1)
        .expect("create contract");

    {
        let (_, balance) = chain_state.get_contract_balance_for_gas(&contract).await.unwrap();
        *balance = 1;
    }

    let deposits = [(XELIS_ASSET, ContractDeposit::Public(1))]
        .into_iter()
        .collect::<IndexMap<_, _>>();
    let decompressed_deposits = HashMap::new();

    let result = vm::invoke_contract(
        ContractCaller::System,
        &mut chain_state,
        Cow::Owned(contract.clone()),
        Some((&deposits, &decompressed_deposits)),
        std::iter::empty(),
        IndexMap::new(),
        100_000,
        InvokeContract::Entry(0),
        Cow::Owned(Default::default()),
        true,
    ).await
        .expect("invoke contract");

    assert!(result.is_success(), "gas injection should be rejected by the contract guard");
    assert_eq!(result.vm_max_gas, 100_000, "rejected injection must not increase VM gas limit");
    assert!(
        chain_state.contract_logs.values().flatten().all(|log| !matches!(log, ContractLog::GasInjection { .. })),
        "rejected injection must not emit a gas injection log"
    );
}

#[tokio::test]
async fn increase_gas_limit_rejects_zero_and_limit_overflow_without_charging() {
    let max_gas = 100_000u64;
    let code = format!(r#"
        entry main() {{
            let before = get_gas_limit();
            require(!increase_gas_limit(0u64), "zero gas injection must be rejected");
            require(get_gas_limit() == before, "zero gas injection must not change the limit");
            require(!increase_gas_limit({limit}u64), "tx gas limit overflow must be rejected");
            require(get_gas_limit() == before, "rejected gas injection must not change the limit");
            return 0
        }}
    "#, limit = MAX_GAS_USAGE_PER_TX);

    let mut chain_state = MockChainState::new();
    let contract = create_contract(&mut chain_state, &code, ContractVersion::V1)
        .expect("create contract");
    let initial_balance = MAX_GAS_USAGE_PER_TX;

    {
        let (_, balance) = chain_state.get_contract_balance_for_gas(&contract).await.unwrap();
        *balance = initial_balance;
    }

    let result = vm::invoke_contract(
        ContractCaller::System,
        &mut chain_state,
        Cow::Owned(contract.clone()),
        None,
        std::iter::empty(),
        IndexMap::new(),
        max_gas,
        InvokeContract::Entry(0),
        Cow::Owned(Default::default()),
        true,
    ).await
        .expect("invoke contract");

    assert!(result.is_success(), "contract should handle rejected gas injections");
    assert_eq!(result.vm_max_gas, max_gas, "rejected gas injections must not raise VM gas limit");

    {
        let (_, balance) = chain_state.get_contract_balance_for_gas(&contract).await.unwrap();
        assert_eq!(*balance, initial_balance, "rejected gas injections must not charge balance");
    }

    assert!(
        chain_state.contract_logs.values().flatten().all(|log| !matches!(log, ContractLog::GasInjection { .. })),
        "rejected gas injections must not emit gas injection logs"
    );
}

#[tokio::test]
async fn transaction_refund_gas_is_paid_only_to_tx_source() {
    let code = r#"
        entry main() {
            return 0
        }
    "#;
    let max_gas = 100_000u64;

    let mut chain_state = MockChainState::new();
    let contract = create_contract(&mut chain_state, code, ContractVersion::V1)
        .expect("create contract");

    let mut account = TrackedAccount::new();
    account.set_balance(XELIS_ASSET, 1_000_000);

    let data = TransactionTypeBuilder::InvokeContract(InvokeContractBuilder {
        contract: contract.clone(),
        entry_id: 0,
        max_gas,
        parameters: Vec::new(),
        deposits: Default::default(),
        permission: Default::default(),
    });
    let mut builder_state = TrackedAccountState {
        balances: account.balances.clone(),
        nonce: account.nonce,
        reference: Reference { topoheight: 0, hash: Hash::zero() },
    };
    let tx = Arc::new(TransactionBuilder::new(
        TxVersion::V2,
        account.keypair.get_public_key().compress(),
        None,
        data,
        FeeBuilder::default(),
    ).build(&mut builder_state, &account.keypair).expect("build tx"));
    let tx_hash = tx.hash();

    let source = account.keypair.get_public_key().compress();
    chain_state.accounts.insert(source.clone(), MockAccount {
        balances: [(XELIS_ASSET, account.keypair.get_public_key().encrypt(0u64))]
            .into_iter()
            .collect(),
        nonce: 0,
    });

    let bystander = KeyPair::new();
    let bystander_source = bystander.get_public_key().compress();
    chain_state.accounts.insert(bystander_source.clone(), MockAccount {
        balances: [(XELIS_ASSET, bystander.get_public_key().encrypt(0u64))]
            .into_iter()
            .collect(),
        nonce: 0,
    });

    let result = vm::invoke_contract(
        ContractCaller::Transaction(&tx_hash, &tx),
        &mut chain_state,
        Cow::Owned(contract),
        None,
        std::iter::empty(),
        IndexMap::new(),
        max_gas,
        InvokeContract::Entry(0),
        Cow::Owned(Default::default()),
        true,
    ).await
        .expect("invoke contract");

    assert!(result.is_success(), "noop contract should succeed: {:?}", result);
    assert!(result.used_gas <= max_gas, "noop must not exceed the tx gas limit");

    let expected_refund = max_gas - result.used_gas;
    assert_account_xelis_balance(
        &chain_state,
        &account.keypair,
        &source,
        expected_refund,
        "unused tx gas must be refunded to the transaction source"
    );
    assert_account_xelis_balance(
        &chain_state,
        &bystander,
        &bystander_source,
        0,
        "unused tx gas must not be refunded to unrelated accounts"
    );
    assert_eq!(
        refund_gas_amount(&chain_state, &tx_hash),
        expected_refund,
        "refund log must match the amount credited to the tx source"
    );
    assert_eq!(
        chain_state.gas_fee + chain_state.burned_fee + expected_refund,
        max_gas,
        "tx gas input must be conserved between fee, burn, and refund"
    );
}

#[tokio::test]
async fn successful_increase_gas_limit_charges_extra_gas_used() {
    let max_gas = 50_000u64;
    let injection = 150_000u64;
    let target_gas = max_gas + 25_000;
    let code = format!(r#"
        entry main() {{
            require(increase_gas_limit({injection}u64), "gas injection must succeed");
            let i: u64 = 0;
            while get_gas_usage() < {target_gas}u64 {{
                i += 1;
            }}
            return 0
        }}
    "#);

    let mut chain_state = MockChainState::new();
    let contract = create_contract(&mut chain_state, &code, ContractVersion::V1)
        .expect("create contract");

    {
        let (_, balance) = chain_state.get_contract_balance_for_gas(&contract).await.unwrap();
        *balance = injection;
    }

    let result = vm::invoke_contract(
        ContractCaller::System,
        &mut chain_state,
        Cow::Owned(contract.clone()),
        None,
        std::iter::empty(),
        IndexMap::new(),
        max_gas,
        InvokeContract::Entry(0),
        Cow::Owned(Default::default()),
        true,
    ).await
        .expect("invoke contract");

    assert!(result.is_success(), "contract should succeed after using injected gas: {:?}", result);
    assert_eq!(result.vm_max_gas, max_gas + injection);
    assert!(result.used_gas > max_gas, "test must consume gas above the original tx limit");
    assert!(result.used_gas <= result.vm_max_gas, "used gas must remain capped by the raised VM limit");

    let extra_used = result.used_gas - max_gas;
    {
        let (_, balance) = chain_state.get_contract_balance_for_gas(&contract).await.unwrap();
        assert_eq!(
            *balance,
            injection - extra_used,
            "contract must pay exactly the gas used above the original tx limit"
        );
    }

    let logs = chain_state.contract_logs.get(&Hash::zero())
        .expect("system caller logs");
    assert!(
        logs.iter().any(|log| matches!(
            log,
            ContractLog::GasInjection { contract: logged_contract, amount }
                if logged_contract == &contract && *amount == extra_used
        )),
        "consumed injected gas must be logged"
    );
}

#[tokio::test]
async fn failed_increase_gas_limit_charges_extra_gas_used() {
    let max_gas = 50_000u64;
    let injection = 150_000u64;
    let target_gas = max_gas + 25_000;
    let code = format!(r#"
        entry main() {{
            require(increase_gas_limit({injection}u64), "gas injection must succeed");
            let i: u64 = 0;
            while get_gas_usage() < {target_gas}u64 {{
                i += 1;
            }}
            require(false, "fail after consuming injected gas");
            return 0
        }}
    "#);

    let mut chain_state = MockChainState::new();
    let contract = create_contract(&mut chain_state, &code, ContractVersion::V1)
        .expect("create contract");

    {
        let (_, balance) = chain_state.get_contract_balance_for_gas(&contract).await.unwrap();
        *balance = injection;
    }

    let result = vm::invoke_contract(
        ContractCaller::System,
        &mut chain_state,
        Cow::Owned(contract.clone()),
        None,
        std::iter::empty(),
        IndexMap::new(),
        max_gas,
        InvokeContract::Entry(0),
        Cow::Owned(Default::default()),
        true,
    ).await
        .expect("invoke contract");

    assert!(!result.is_success(), "contract must fail after using injected gas");
    assert_eq!(result.vm_max_gas, max_gas + injection);
    assert!(result.used_gas > max_gas, "failed execution must preserve gas used above the original tx limit");
    assert!(result.used_gas <= result.vm_max_gas, "used gas must remain capped by the raised VM limit");

    let extra_used = result.used_gas - max_gas;
    {
        let (_, balance) = chain_state.get_contract_balance_for_gas(&contract).await.unwrap();
        assert_eq!(
            *balance,
            injection - extra_used,
            "failed execution must still charge the contract-funded extra gas it consumed"
        );
    }

    let logs = chain_state.contract_logs.get(&Hash::zero())
        .expect("system caller logs");
    assert!(
        logs.iter().any(|log| matches!(
            log,
            ContractLog::GasInjection { contract: logged_contract, amount }
                if logged_contract == &contract && *amount == extra_used
        )),
        "failed execution must log consumed injected gas"
    );
}

#[tokio::test]
async fn successful_account_paid_scheduled_execution_keeps_reserved_gas_funded() {
    let code = r#"
        pub fn callback(args: any[]) -> u64 {
            return 0
        }

        entry main() {
            let execution = ScheduledExecution::new_at_block_end(callback, [], 50000u64, false);
            require(execution != null, "scheduled execution was not created");
            return 0
        }
    "#;

    let mut chain_state = MockChainState::new();
    let contract = create_contract(&mut chain_state, code, ContractVersion::V1)
        .expect("create contract");

    let source = KeyPair::new().get_public_key().compress();
    let max_gas = 100000u64;

    let result = vm::invoke_contract(
        ContractCaller::Impersonate(Cow::Owned(source)),
        &mut chain_state,
        Cow::Owned(contract),
        None,
        std::iter::empty(),
        IndexMap::new(),
        max_gas,
        InvokeContract::Entry(1),
        Cow::Owned(Default::default()),
        true,
    ).await
        .expect("invoke contract");

    assert!(result.is_success(), "scheduling should succeed: {:?}", result);
    assert_eq!(
        chain_state.executions.block_end.len(),
        1,
        "scheduled execution must be registered"
    );

    let synthetic_caller = Hash::zero();
    let refund = refund_gas_amount(&chain_state, &synthetic_caller);
    assert!(
        refund <= max_gas - 50000,
        "outer refund must not include gas reserved for the future scheduled execution"
    );
}

#[tokio::test]
async fn failed_account_paid_scheduled_execution_refunds_only_current_input() {
    let code = r#"
        pub fn callback(args: any[]) -> u64 {
            return 0
        }

        entry main() {
            let execution = ScheduledExecution::new_at_block_end(callback, [], 50000u64, false);
            require(execution != null, "scheduled execution was not created");
            require(false, "fail after reserving scheduled gas");
            return 0
        }
    "#;

    let mut chain_state = MockChainState::new();
    let contract = create_contract(&mut chain_state, code, ContractVersion::V1)
        .expect("create contract");

    let source = KeyPair::new().get_public_key().compress();
    let max_gas = 100000u64;

    let result = vm::invoke_contract(
        ContractCaller::Impersonate(Cow::Owned(source)),
        &mut chain_state,
        Cow::Owned(contract),
        None,
        std::iter::empty(),
        IndexMap::new(),
        max_gas,
        InvokeContract::Entry(1),
        Cow::Owned(Default::default()),
        true,
    ).await
        .expect("invoke contract");

    assert!(!result.is_success(), "contract must fail after reserving scheduled gas");
    assert!(
        chain_state.executions.block_end.is_empty(),
        "failed execution must not commit the scheduled execution"
    );

    let synthetic_caller = Hash::zero();
    let refund = refund_gas_amount(&chain_state, &synthetic_caller);
    assert!(
        refund <= max_gas,
        "failed execution refund must never exceed the original tx gas input"
    );
    assert!(
        refund > max_gas - 50000,
        "discarded scheduled gas allowance should be refundable on failure"
    );
}

#[tokio::test]
async fn block_end_noop_near_max_gas_pays_fee_and_refunds_only_leftover() {
    let schedule_max_gas = MAX_GAS_USAGE_PER_TX - 50_000;
    let code = format!(r#"
        pub fn callback() -> u64 {{
            return 0
        }}

        entry main() {{
            let execution = ScheduledExecution::new_at_block_end(callback, [], {schedule_max_gas}u64, false);
            require(execution != null, "scheduled execution was not created");
            return 0
        }}
    "#);

    let mut chain_state = MockChainState::new();
    let contract = create_contract(&mut chain_state, &code, ContractVersion::V1)
        .expect("create contract");

    let keypair = KeyPair::new();
    let source = keypair.get_public_key().compress();
    chain_state.accounts.insert(source.clone(), MockAccount {
        balances: [(XELIS_ASSET, keypair.get_public_key().encrypt(0u64))]
            .into_iter()
            .collect(),
        nonce: 0,
    });

    let result = vm::invoke_contract(
        ContractCaller::Impersonate(Cow::Owned(source.clone())),
        &mut chain_state,
        Cow::Owned(contract.clone()),
        None,
        std::iter::empty(),
        IndexMap::new(),
        MAX_GAS_USAGE_PER_TX,
        InvokeContract::Entry(1),
        Cow::Owned(Default::default()),
        true,
    ).await
        .expect("invoke scheduler");

    assert!(result.is_success(), "scheduling should succeed: {:?}", result);
    assert_eq!(
        chain_state.executions.block_end.len(),
        1,
        "block-end execution must be registered"
    );

    let gas_fee_before = chain_state.gas_fee;
    let burned_fee_before = chain_state.burned_fee;
    let execution_hash = chain_state.executions.block_end.pop()
        .expect("block-end execution hash");
    let execution = chain_state.executions.executions.remove(&execution_hash)
        .expect("scheduled execution");

    assert_eq!(
        execution.max_gas,
        schedule_max_gas,
        "scheduled execution should reserve almost the tx gas limit"
    );

    let execution_result = vm::invoke_contract(
        ContractCaller::Scheduled(
            Cow::Owned(execution.hash.as_ref().clone()),
            Cow::Owned(execution.contract.clone())
        ),
        &mut chain_state,
        Cow::Owned(execution.contract),
        None,
        execution.params.into_iter(),
        execution.gas_sources,
        execution.max_gas,
        InvokeContract::Chunk(execution.chunk_id, false),
        Cow::Owned(InterContractPermission::All),
        true,
    ).await
        .expect("invoke scheduled noop");

    assert!(
        execution_result.is_success(),
        "scheduled noop should succeed: {:?}",
        execution_result
    );
    assert!(
        execution_result.used_gas < schedule_max_gas,
        "noop should leave gas to refund"
    );

    let expected_burned_gas = execution_result.used_gas * TX_GAS_BURN_PERCENT / 100;
    let expected_fee_gas = execution_result.used_gas - expected_burned_gas;
    assert_eq!(execution_result.burned_gas, expected_burned_gas);
    assert_eq!(execution_result.fee_gas, expected_fee_gas);

    assert_account_gas_conservation(
        &chain_state,
        &keypair,
        &source,
        schedule_max_gas,
        execution_result.used_gas,
        gas_fee_before,
        burned_fee_before,
    );
}

#[tokio::test]
async fn delayed_topoheight_noop_pays_fee_and_refunds_only_leftover() {
    let scheduled_gas = 200000u64;
    let code = format!(r#"
        pub fn callback() -> u64 {{
            return 0
        }}

        entry main() {{
            let execution = ScheduledExecution::new_at_topoheight(callback, [], {scheduled_gas}u64, false, 42u64);
            require(execution != null, "scheduled execution was not created");
            return 0
        }}
    "#);

    let mut chain_state = MockChainState::new();
    let contract = create_contract(&mut chain_state, &code, ContractVersion::V1)
        .expect("create contract");

    let keypair = KeyPair::new();
    let source = keypair.get_public_key().compress();
    chain_state.accounts.insert(source.clone(), MockAccount {
        balances: [(XELIS_ASSET, keypair.get_public_key().encrypt(0u64))]
            .into_iter()
            .collect(),
        nonce: 0,
    });

    let result = vm::invoke_contract(
        ContractCaller::Impersonate(Cow::Owned(source.clone())),
        &mut chain_state,
        Cow::Owned(contract.clone()),
        None,
        std::iter::empty(),
        IndexMap::new(),
        300000,
        InvokeContract::Entry(1),
        Cow::Owned(Default::default()),
        true,
    ).await
        .expect("invoke scheduler");

    assert!(result.is_success(), "delayed scheduling should succeed: {:?}", result);
    assert_eq!(
        chain_state.executions.at_topoheight.len(),
        1,
        "delayed execution must be registered"
    );

    let gas_fee_before = chain_state.gas_fee;
    let burned_fee_before = chain_state.burned_fee;
    let execution_hash = chain_state.executions.at_topoheight.pop()
        .expect("delayed execution hash");
    let execution = chain_state.executions.executions.remove(&execution_hash)
        .expect("scheduled execution");

    assert_eq!(execution.max_gas, scheduled_gas);

    let execution_result = vm::invoke_contract(
        ContractCaller::Scheduled(
            Cow::Owned(execution.hash.as_ref().clone()),
            Cow::Owned(execution.contract.clone())
        ),
        &mut chain_state,
        Cow::Owned(execution.contract),
        None,
        execution.params.into_iter(),
        execution.gas_sources,
        execution.max_gas,
        InvokeContract::Chunk(execution.chunk_id, false),
        Cow::Owned(InterContractPermission::All),
        true,
    ).await
        .expect("invoke delayed noop");

    assert!(
        execution_result.is_success(),
        "delayed noop should succeed: {:?}",
        execution_result
    );
    assert!(
        execution_result.used_gas < scheduled_gas,
        "delayed noop should leave gas to refund"
    );
    assert_eq!(
        execution_result.burned_gas,
        execution_result.used_gas * TX_GAS_BURN_PERCENT / 100
    );
    assert_eq!(
        execution_result.fee_gas,
        execution_result.used_gas - execution_result.burned_gas
    );

    assert_account_gas_conservation(
        &chain_state,
        &keypair,
        &source,
        scheduled_gas,
        execution_result.used_gas,
        gas_fee_before,
        burned_fee_before,
    );
}

#[tokio::test]
async fn contract_balance_paid_block_end_noop_pays_fee_and_refunds_only_leftover() {
    let scheduled_gas = 50000u64;
    let initial_balance = scheduled_gas + COST_PER_SCHEDULED_EXECUTION_AT_BLOCK_END + 1000;
    let code = format!(r#"
        pub fn callback() -> u64 {{
            return 0
        }}

        entry main() {{
            let execution = ScheduledExecution::new_at_block_end(callback, [], {scheduled_gas}u64, true);
            require(execution != null, "scheduled execution was not created");
            return 0
        }}
    "#);

    let mut chain_state = MockChainState::with(BlockVersion::V6);
    let contract = create_contract(&mut chain_state, &code, ContractVersion::V1)
        .expect("create contract");
    chain_state.set_contract_balance(&contract, &XELIS_ASSET, initial_balance);

    let registration = vm::invoke_contract(
        ContractCaller::System,
        &mut chain_state,
        Cow::Owned(contract.clone()),
        None,
        std::iter::empty(),
        IndexMap::new(),
        100000,
        InvokeContract::Entry(1),
        Cow::Owned(Default::default()),
        true,
    ).await
        .expect("invoke scheduler");

    assert!(
        registration.is_success(),
        "contract-balance scheduling should succeed: {:?}",
        registration
    );
    let balance_after_registration = chain_state.get_contract_balance(&contract, &XELIS_ASSET);
    assert!(
        balance_after_registration < initial_balance - scheduled_gas,
        "contract balance should pay both reserved gas and scheduling overhead"
    );

    let gas_fee_before = chain_state.gas_fee;
    let burned_fee_before = chain_state.burned_fee;
    let execution_hash = chain_state.executions.block_end.pop()
        .expect("block-end execution hash");
    let execution = chain_state.executions.executions.remove(&execution_hash)
        .expect("scheduled execution");

    let execution_result = vm::invoke_contract(
        ContractCaller::Scheduled(
            Cow::Owned(execution.hash.as_ref().clone()),
            Cow::Owned(execution.contract.clone())
        ),
        &mut chain_state,
        Cow::Owned(execution.contract),
        None,
        execution.params.into_iter(),
        execution.gas_sources,
        execution.max_gas,
        InvokeContract::Chunk(execution.chunk_id, false),
        Cow::Owned(InterContractPermission::All),
        true,
    ).await
        .expect("invoke scheduled noop");

    assert!(
        execution_result.is_success(),
        "contract-funded scheduled noop should succeed: {:?}",
        execution_result
    );
    assert!(
        execution_result.used_gas < scheduled_gas,
        "contract-funded noop should leave gas to refund"
    );

    let gas_fee_delta = chain_state.gas_fee - gas_fee_before;
    let burned_fee_delta = chain_state.burned_fee - burned_fee_before;
    assert_eq!(
        gas_fee_delta,
        execution_result.used_gas - execution_result.burned_gas,
        "miner fee must be charged only from gas actually used"
    );
    assert_eq!(
        burned_fee_delta,
        execution_result.burned_gas,
        "burned fee must be charged only from gas actually used"
    );

    assert_eq!(
        chain_state.get_contract_balance(&contract, &XELIS_ASSET) - balance_after_registration,
        scheduled_gas - execution_result.used_gas,
        "callback execution must refund only unused reserved gas"
    );
    assert_eq!(
        chain_state.get_contract_balance(&contract, &XELIS_ASSET) - balance_after_registration
            + gas_fee_delta
            + burned_fee_delta,
        scheduled_gas,
        "callback gas accounting must conserve the reserved contract input"
    );
}

#[tokio::test]
async fn block_end_noop_without_scheduling_headroom_fails_without_committing_execution() {
    let schedule_max_gas = MAX_GAS_USAGE_PER_TX - 1;
    let code = format!(r#"
        pub fn callback() -> u64 {{
            return 0
        }}

        entry main() {{
            let execution = ScheduledExecution::new_at_block_end(callback, [], {schedule_max_gas}u64, false);
            require(execution != null, "scheduled execution was not created");
            return 0
        }}
    "#);

    let mut chain_state = MockChainState::new();
    let contract = create_contract(&mut chain_state, &code, ContractVersion::V1)
        .expect("create contract");

    let source = KeyPair::new().get_public_key().compress();
    let result = vm::invoke_contract(
        ContractCaller::Impersonate(Cow::Owned(source)),
        &mut chain_state,
        Cow::Owned(contract),
        None,
        std::iter::empty(),
        IndexMap::new(),
        MAX_GAS_USAGE_PER_TX,
        InvokeContract::Entry(1),
        Cow::Owned(Default::default()),
        true,
    ).await
        .expect("invoke scheduler");

    assert!(
        !result.is_success(),
        "scheduling must fail when reserved gas leaves no room for scheduling overhead"
    );
    assert!(
        chain_state.executions.block_end.is_empty(),
        "failed scheduling must not register a block-end execution"
    );
    assert!(
        chain_state.executions.executions.is_empty(),
        "failed scheduling must not commit the execution object"
    );
    assert!(
        result.used_gas <= MAX_GAS_USAGE_PER_TX,
        "failed scheduling must not report gas above tx input"
    );
}

#[tokio::test]
async fn account_paid_scheduled_execution_increase_max_gas_conserves_funds() {
    let initial_gas = 40_000u64;
    let extra_gas = 20_000u64;
    let total_reserved = initial_gas + extra_gas;
    let code = format!(r#"
        pub fn callback() -> u64 {{
            return 0
        }}

        entry main() {{
            let execution = ScheduledExecution::new_at_block_end(callback, [], {initial_gas}u64, false)
                .expect("scheduled execution");
            require(execution.increase_max_gas({extra_gas}u64, false), "gas increase must succeed");
            require(execution.get_max_gas() == {total_reserved}u64, "bad max gas after increase");
            return 0
        }}
    "#);

    let mut chain_state = MockChainState::new();
    let contract = create_contract(&mut chain_state, &code, ContractVersion::V1)
        .expect("create contract");

    let keypair = KeyPair::new();
    let source = keypair.get_public_key().compress();
    chain_state.accounts.insert(source.clone(), MockAccount {
        balances: [(XELIS_ASSET, keypair.get_public_key().encrypt(0u64))]
            .into_iter()
            .collect(),
        nonce: 0,
    });

    let result = vm::invoke_contract(
        ContractCaller::Impersonate(Cow::Owned(source.clone())),
        &mut chain_state,
        Cow::Owned(contract.clone()),
        None,
        std::iter::empty(),
        IndexMap::new(),
        150_000,
        InvokeContract::Entry(1),
        Cow::Owned(Default::default()),
        true,
    ).await
        .expect("invoke scheduler");

    assert!(result.is_success(), "scheduling with gas increase should succeed: {:?}", result);

    let execution_hash = chain_state.executions.block_end.pop()
        .expect("block-end execution hash");
    let execution = chain_state.executions.executions.remove(&execution_hash)
        .expect("scheduled execution");

    assert_eq!(execution.max_gas, total_reserved);
    assert_eq!(
        execution.gas_sources.get(&Source::Account(source.clone())).copied(),
        Some(total_reserved),
        "same account source must fund both initial and increased scheduled gas"
    );

    let gas_fee_before = chain_state.gas_fee;
    let burned_fee_before = chain_state.burned_fee;
    let execution_result = vm::invoke_contract(
        ContractCaller::Scheduled(
            Cow::Owned(execution.hash.as_ref().clone()),
            Cow::Owned(execution.contract.clone())
        ),
        &mut chain_state,
        Cow::Owned(execution.contract),
        None,
        execution.params.into_iter(),
        execution.gas_sources,
        execution.max_gas,
        InvokeContract::Chunk(execution.chunk_id, false),
        Cow::Owned(InterContractPermission::All),
        true,
    ).await
        .expect("invoke scheduled noop");

    assert!(execution_result.is_success(), "scheduled noop should succeed: {:?}", execution_result);
    assert_account_gas_conservation(
        &chain_state,
        &keypair,
        &source,
        total_reserved,
        execution_result.used_gas,
        gas_fee_before,
        burned_fee_before,
    );
}

#[tokio::test]
async fn account_paid_scheduled_execution_with_contract_gas_injection_above_reserved_gas_succeeds() {
    let scheduled_gas = 40_000u64;
    let injection = 80_000u64;
    let target_gas = scheduled_gas + 20_000;
    let initial_contract_balance = injection + 1_000;
    let code = format!(r#"
        pub fn callback() -> u64 {{
            require(increase_gas_limit({injection}u64), "gas injection must succeed");
            let i: u64 = 0;
            while get_gas_usage() < {target_gas}u64 {{
                i += 1;
            }}
            return 0
        }}

        entry main() {{
            let execution = ScheduledExecution::new_at_block_end(callback, [], {scheduled_gas}u64, false)
                .expect("scheduled execution");
            return 0
        }}
    "#);

    let mut chain_state = MockChainState::new();
    let contract = create_contract(&mut chain_state, &code, ContractVersion::V1)
        .expect("create contract");
    chain_state.set_contract_balance(&contract, &XELIS_ASSET, initial_contract_balance);

    let keypair = KeyPair::new();
    let source = keypair.get_public_key().compress();
    chain_state.accounts.insert(source.clone(), MockAccount {
        balances: [(XELIS_ASSET, keypair.get_public_key().encrypt(0u64))]
            .into_iter()
            .collect(),
        nonce: 0,
    });

    let registration = vm::invoke_contract(
        ContractCaller::Impersonate(Cow::Owned(source.clone())),
        &mut chain_state,
        Cow::Owned(contract.clone()),
        None,
        std::iter::empty(),
        IndexMap::new(),
        150_000,
        InvokeContract::Entry(1),
        Cow::Owned(Default::default()),
        true,
    ).await
        .expect("invoke scheduler");

    assert!(registration.is_success(), "scheduling should succeed: {:?}", registration);

    let account_balance_before_execution = chain_state.accounts.get(&source)
        .unwrap()
        .balances[&XELIS_ASSET]
        .clone();
    let balance_before_execution = chain_state.get_contract_balance(&contract, &XELIS_ASSET);
    let execution_hash = chain_state.executions.block_end.pop()
        .expect("block-end execution hash");
    let execution = chain_state.executions.executions.remove(&execution_hash)
        .expect("scheduled execution");

    let execution_result = vm::invoke_contract(
        ContractCaller::Scheduled(
            Cow::Owned(execution.hash.as_ref().clone()),
            Cow::Owned(execution.contract.clone())
        ),
        &mut chain_state,
        Cow::Owned(execution.contract),
        None,
        execution.params.into_iter(),
        execution.gas_sources,
        execution.max_gas,
        InvokeContract::Chunk(execution.chunk_id, false),
        Cow::Owned(InterContractPermission::All),
        true,
    ).await
        .expect("invoke scheduled callback with gas injection");

    assert!(execution_result.is_success(), "scheduled callback should succeed: {:?}", execution_result);
    assert_eq!(execution_result.vm_max_gas, scheduled_gas + injection);
    assert!(
        execution_result.used_gas > scheduled_gas,
        "test must consume contract-injected gas above the account-funded reservation"
    );
    assert!(
        execution_result.used_gas <= MAX_GAS_USAGE_PER_TX,
        "execution must remain bounded by the global VM gas limit"
    );
    assert!(
        execution_result.used_gas <= execution_result.vm_max_gas,
        "used gas must remain capped by the raised VM limit"
    );
    assert_eq!(
        keypair.decrypt_to_point(&chain_state.accounts.get(&source).unwrap().balances[&XELIS_ASSET]),
        keypair.decrypt_to_point(&account_balance_before_execution),
        "account source must not receive a refund once all reserved scheduled gas is consumed"
    );

    let extra_used_gas = execution_result.used_gas - scheduled_gas;
    assert_eq!(
        balance_before_execution - chain_state.get_contract_balance(&contract, &XELIS_ASSET),
        extra_used_gas,
        "contract must pay only gas used above the account-funded reservation"
    );
    assert!(
        chain_state.contract_logs
            .values()
            .flatten()
            .any(|log| matches!(
                log,
                ContractLog::GasInjection {
                    contract: logged_contract,
                    amount
                } if logged_contract == &contract && *amount == extra_used_gas
            )),
        "contract gas injection consumption must be logged"
    );
}

#[tokio::test]
async fn scheduled_execution_with_unused_contract_gas_injection_refunds_each_pool_once() {
    let scheduled_gas = 80_000u64;
    let injection = 40_000u64;
    let initial_contract_balance = injection + 1_000;
    let code = format!(r#"
        pub fn callback() -> u64 {{
            require(increase_gas_limit({injection}u64), "gas injection must succeed");
            return 0
        }}

        entry main() {{
            let execution = ScheduledExecution::new_at_block_end(callback, [], {scheduled_gas}u64, false)
                .expect("scheduled execution");
            return 0
        }}
    "#);

    let mut chain_state = MockChainState::new();
    let contract = create_contract(&mut chain_state, &code, ContractVersion::V1)
        .expect("create contract");
    chain_state.set_contract_balance(&contract, &XELIS_ASSET, initial_contract_balance);

    let keypair = KeyPair::new();
    let source = keypair.get_public_key().compress();
    chain_state.accounts.insert(source.clone(), MockAccount {
        balances: [(XELIS_ASSET, keypair.get_public_key().encrypt(0u64))]
            .into_iter()
            .collect(),
        nonce: 0,
    });

    let registration = vm::invoke_contract(
        ContractCaller::Impersonate(Cow::Owned(source.clone())),
        &mut chain_state,
        Cow::Owned(contract.clone()),
        None,
        std::iter::empty(),
        IndexMap::new(),
        150_000,
        InvokeContract::Entry(1),
        Cow::Owned(Default::default()),
        true,
    ).await
        .expect("invoke scheduler");

    assert!(registration.is_success(), "scheduling should succeed: {:?}", registration);

    let account_balance_before_execution = chain_state.accounts.get(&source)
        .unwrap()
        .balances[&XELIS_ASSET]
        .clone();
    let balance_before_execution = chain_state.get_contract_balance(&contract, &XELIS_ASSET);
    let gas_fee_before = chain_state.gas_fee;
    let burned_fee_before = chain_state.burned_fee;
    let execution_hash = chain_state.executions.block_end.pop()
        .expect("block-end execution hash");
    let execution = chain_state.executions.executions.remove(&execution_hash)
        .expect("scheduled execution");

    let execution_result = vm::invoke_contract(
        ContractCaller::Scheduled(
            Cow::Owned(execution.hash.as_ref().clone()),
            Cow::Owned(execution.contract.clone())
        ),
        &mut chain_state,
        Cow::Owned(execution.contract),
        None,
        execution.params.into_iter(),
        execution.gas_sources,
        execution.max_gas,
        InvokeContract::Chunk(execution.chunk_id, false),
        Cow::Owned(InterContractPermission::All),
        true,
    ).await
        .expect("invoke scheduled callback with unused gas injection");

    assert!(execution_result.is_success(), "scheduled callback should succeed: {:?}", execution_result);
    assert_eq!(execution_result.vm_max_gas, scheduled_gas + injection);
    assert!(
        execution_result.used_gas < scheduled_gas,
        "test must leave scheduled gas to refund"
    );

    let scheduled_refund = scheduled_gas - execution_result.used_gas;
    assert_eq!(
        keypair.decrypt_to_point(&chain_state.accounts.get(&source).unwrap().balances[&XELIS_ASSET]),
        keypair.decrypt_to_point(&account_balance_before_execution) + Scalar::from(scheduled_refund) * (*G),
        "account source must receive only the unused scheduled gas"
    );
    assert_eq!(
        chain_state.get_contract_balance(&contract, &XELIS_ASSET),
        balance_before_execution,
        "fully unused runtime gas injection must be refunded to the contract"
    );
    assert_eq!(
        scheduled_refund + chain_state.gas_fee - gas_fee_before + chain_state.burned_fee - burned_fee_before,
        scheduled_gas,
        "scheduled source pool must conserve independently from runtime injections"
    );
    assert!(
        !chain_state.contract_logs
            .values()
            .flatten()
            .any(|log| matches!(
                log,
                ContractLog::GasInjection {
                    contract: logged_contract,
                    ..
                } if logged_contract == &contract
            )),
        "unused runtime gas injection must not be logged as consumed"
    );
}

#[tokio::test]
async fn failed_scheduled_execution_charges_used_contract_gas_injection_above_reserved_gas() {
    let scheduled_gas = 40_000u64;
    let injection = 80_000u64;
    let target_gas = scheduled_gas + 20_000;
    let initial_contract_balance = injection + 1_000;
    let code = format!(r#"
        pub fn callback() -> u64 {{
            require(increase_gas_limit({injection}u64), "gas injection must succeed");
            let i: u64 = 0;
            while get_gas_usage() < {target_gas}u64 {{
                i += 1;
            }}
            require(false, "fail after consuming injected gas");
            return 0
        }}

        entry main() {{
            let execution = ScheduledExecution::new_at_block_end(callback, [], {scheduled_gas}u64, false)
                .expect("scheduled execution");
            return 0
        }}
    "#);

    let mut chain_state = MockChainState::new();
    let contract = create_contract(&mut chain_state, &code, ContractVersion::V1)
        .expect("create contract");
    chain_state.set_contract_balance(&contract, &XELIS_ASSET, initial_contract_balance);

    let keypair = KeyPair::new();
    let source = keypair.get_public_key().compress();
    chain_state.accounts.insert(source.clone(), MockAccount {
        balances: [(XELIS_ASSET, keypair.get_public_key().encrypt(0u64))]
            .into_iter()
            .collect(),
        nonce: 0,
    });

    let registration = vm::invoke_contract(
        ContractCaller::Impersonate(Cow::Owned(source.clone())),
        &mut chain_state,
        Cow::Owned(contract.clone()),
        None,
        std::iter::empty(),
        IndexMap::new(),
        150_000,
        InvokeContract::Entry(1),
        Cow::Owned(Default::default()),
        true,
    ).await
        .expect("invoke scheduler");

    assert!(registration.is_success(), "scheduling should succeed: {:?}", registration);

    let account_balance_before_execution = chain_state.accounts.get(&source)
        .unwrap()
        .balances[&XELIS_ASSET]
        .clone();
    let balance_before_execution = chain_state.get_contract_balance(&contract, &XELIS_ASSET);
    let execution_hash = chain_state.executions.block_end.pop()
        .expect("block-end execution hash");
    let execution = chain_state.executions.executions.remove(&execution_hash)
        .expect("scheduled execution");

    let execution_result = vm::invoke_contract(
        ContractCaller::Scheduled(
            Cow::Owned(execution.hash.as_ref().clone()),
            Cow::Owned(execution.contract.clone())
        ),
        &mut chain_state,
        Cow::Owned(execution.contract),
        None,
        execution.params.into_iter(),
        execution.gas_sources,
        execution.max_gas,
        InvokeContract::Chunk(execution.chunk_id, false),
        Cow::Owned(InterContractPermission::All),
        true,
    ).await
        .expect("invoke failed scheduled callback with gas injection");

    assert!(!execution_result.is_success(), "scheduled callback should fail after using injected gas");
    assert_eq!(execution_result.vm_max_gas, scheduled_gas + injection);
    assert!(
        execution_result.used_gas > scheduled_gas,
        "test must consume injected gas above the scheduled source pool"
    );
    assert!(
        execution_result.used_gas <= execution_result.vm_max_gas,
        "used gas must remain capped by the raised VM limit"
    );
    assert_eq!(
        keypair.decrypt_to_point(&chain_state.accounts.get(&source).unwrap().balances[&XELIS_ASSET]),
        keypair.decrypt_to_point(&account_balance_before_execution),
        "scheduled source must not be refunded once all reserved gas is consumed"
    );

    let extra_used_gas = execution_result.used_gas - scheduled_gas;
    assert_eq!(
        balance_before_execution - chain_state.get_contract_balance(&contract, &XELIS_ASSET),
        extra_used_gas,
        "failed execution must still charge only the injected gas it consumed above the scheduled source pool"
    );
    assert!(
        chain_state.contract_logs
            .values()
            .flatten()
            .any(|log| matches!(
                log,
                ContractLog::GasInjection {
                    contract: logged_contract,
                    amount
                } if logged_contract == &contract && *amount == extra_used_gas
            )),
        "failed scheduled execution must log consumed injected gas"
    );
}

#[tokio::test]
async fn failed_scheduled_execution_refunds_unused_sources_and_unused_contract_gas_injection() {
    let scheduled_gas = 80_000u64;
    let injection = 40_000u64;
    let initial_contract_balance = injection + 1_000;
    let code = format!(r#"
        pub fn callback() -> u64 {{
            require(increase_gas_limit({injection}u64), "gas injection must succeed");
            require(false, "fail before consuming injected gas");
            return 0
        }}

        entry main() {{
            let execution = ScheduledExecution::new_at_block_end(callback, [], {scheduled_gas}u64, false)
                .expect("scheduled execution");
            return 0
        }}
    "#);

    let mut chain_state = MockChainState::new();
    let contract = create_contract(&mut chain_state, &code, ContractVersion::V1)
        .expect("create contract");
    chain_state.set_contract_balance(&contract, &XELIS_ASSET, initial_contract_balance);

    let keypair = KeyPair::new();
    let source = keypair.get_public_key().compress();
    chain_state.accounts.insert(source.clone(), MockAccount {
        balances: [(XELIS_ASSET, keypair.get_public_key().encrypt(0u64))]
            .into_iter()
            .collect(),
        nonce: 0,
    });

    let registration = vm::invoke_contract(
        ContractCaller::Impersonate(Cow::Owned(source.clone())),
        &mut chain_state,
        Cow::Owned(contract.clone()),
        None,
        std::iter::empty(),
        IndexMap::new(),
        150_000,
        InvokeContract::Entry(1),
        Cow::Owned(Default::default()),
        true,
    ).await
        .expect("invoke scheduler");

    assert!(registration.is_success(), "scheduling should succeed: {:?}", registration);

    let account_balance_before_execution = chain_state.accounts.get(&source)
        .unwrap()
        .balances[&XELIS_ASSET]
        .clone();
    let balance_before_execution = chain_state.get_contract_balance(&contract, &XELIS_ASSET);
    let gas_fee_before = chain_state.gas_fee;
    let burned_fee_before = chain_state.burned_fee;
    let execution_hash = chain_state.executions.block_end.pop()
        .expect("block-end execution hash");
    let execution = chain_state.executions.executions.remove(&execution_hash)
        .expect("scheduled execution");

    let execution_result = vm::invoke_contract(
        ContractCaller::Scheduled(
            Cow::Owned(execution.hash.as_ref().clone()),
            Cow::Owned(execution.contract.clone())
        ),
        &mut chain_state,
        Cow::Owned(execution.contract),
        None,
        execution.params.into_iter(),
        execution.gas_sources,
        execution.max_gas,
        InvokeContract::Chunk(execution.chunk_id, false),
        Cow::Owned(InterContractPermission::All),
        true,
    ).await
        .expect("invoke failed scheduled callback with unused gas injection");

    assert!(!execution_result.is_success(), "scheduled callback should fail after injecting gas");
    assert_eq!(execution_result.vm_max_gas, scheduled_gas + injection);
    assert!(
        execution_result.used_gas < scheduled_gas,
        "test must leave scheduled gas to refund"
    );

    let scheduled_refund = scheduled_gas - execution_result.used_gas;
    assert_eq!(
        keypair.decrypt_to_point(&chain_state.accounts.get(&source).unwrap().balances[&XELIS_ASSET]),
        keypair.decrypt_to_point(&account_balance_before_execution) + Scalar::from(scheduled_refund) * (*G),
        "scheduled source must receive only unused scheduled gas"
    );
    assert_eq!(
        chain_state.get_contract_balance(&contract, &XELIS_ASSET),
        balance_before_execution,
        "unused runtime gas injection must not be charged when failed changes are discarded"
    );
    assert_eq!(
        scheduled_refund + chain_state.gas_fee - gas_fee_before + chain_state.burned_fee - burned_fee_before,
        scheduled_gas,
        "failed scheduled source pool must conserve between fee, burn, and refund"
    );
    assert!(
        !chain_state.contract_logs
            .values()
            .flatten()
            .any(|log| matches!(
                log,
                ContractLog::GasInjection {
                    contract: logged_contract,
                    ..
                } if logged_contract == &contract
            )),
        "unused runtime gas injection must not be logged as consumed"
    );
}

#[tokio::test]
async fn contract_paid_scheduled_execution_increase_max_gas_conserves_funds() {
    let initial_gas = 40_000u64;
    let extra_gas = 20_000u64;
    let total_reserved = initial_gas + extra_gas;
    let initial_balance = total_reserved + COST_PER_SCHEDULED_EXECUTION_AT_BLOCK_END + 1_000;
    let code = format!(r#"
        pub fn callback() -> u64 {{
            return 0
        }}

        entry main() {{
            let execution = ScheduledExecution::new_at_block_end(callback, [], {initial_gas}u64, true)
                .expect("scheduled execution");
            require(execution.increase_max_gas({extra_gas}u64, true), "gas increase must succeed");
            require(execution.get_max_gas() == {total_reserved}u64, "bad max gas after increase");
            return 0
        }}
    "#);

    let mut chain_state = MockChainState::with(BlockVersion::V6);
    let contract = create_contract(&mut chain_state, &code, ContractVersion::V1)
        .expect("create contract");
    chain_state.set_contract_balance(&contract, &XELIS_ASSET, initial_balance);

    let registration = vm::invoke_contract(
        ContractCaller::System,
        &mut chain_state,
        Cow::Owned(contract.clone()),
        None,
        std::iter::empty(),
        IndexMap::new(),
        150_000,
        InvokeContract::Entry(1),
        Cow::Owned(Default::default()),
        true,
    ).await
        .expect("invoke scheduler");

    assert!(registration.is_success(), "contract-funded scheduling should succeed: {:?}", registration);
    let balance_after_registration = chain_state.get_contract_balance(&contract, &XELIS_ASSET);
    let paid_at_registration = initial_balance - balance_after_registration;
    let paid_overhead = paid_at_registration - total_reserved;
    assert!(
        paid_overhead >= COST_PER_SCHEDULED_EXECUTION_AT_BLOCK_END,
        "contract must pay initial gas, increased gas, and at least the fixed scheduling overhead"
    );

    let execution_hash = chain_state.executions.block_end.pop()
        .expect("block-end execution hash");
    let execution = chain_state.executions.executions.remove(&execution_hash)
        .expect("scheduled execution");

    assert_eq!(execution.max_gas, total_reserved);
    assert_eq!(
        execution.gas_sources.get(&Source::Contract(contract.clone())).copied(),
        Some(total_reserved),
        "contract source must fund both initial and increased scheduled gas"
    );

    let gas_fee_before = chain_state.gas_fee;
    let burned_fee_before = chain_state.burned_fee;
    let execution_result = vm::invoke_contract(
        ContractCaller::Scheduled(
            Cow::Owned(execution.hash.as_ref().clone()),
            Cow::Owned(execution.contract.clone())
        ),
        &mut chain_state,
        Cow::Owned(execution.contract),
        None,
        execution.params.into_iter(),
        execution.gas_sources,
        execution.max_gas,
        InvokeContract::Chunk(execution.chunk_id, false),
        Cow::Owned(InterContractPermission::All),
        true,
    ).await
        .expect("invoke scheduled noop");

    assert!(execution_result.is_success(), "scheduled noop should succeed: {:?}", execution_result);
    let gas_fee_delta = chain_state.gas_fee - gas_fee_before;
    let burned_fee_delta = chain_state.burned_fee - burned_fee_before;
    let refund_delta = chain_state.get_contract_balance(&contract, &XELIS_ASSET) - balance_after_registration;

    assert_eq!(gas_fee_delta, execution_result.fee_gas);
    assert_eq!(burned_fee_delta, execution_result.burned_gas);
    assert_eq!(
        refund_delta + gas_fee_delta + burned_fee_delta,
        total_reserved,
        "scheduled execution must conserve contract-funded reserved gas"
    );
}

#[tokio::test]
async fn failed_account_paid_scheduled_execution_after_increase_refunds_reserved_gas() {
    let initial_gas = 40_000u64;
    let extra_gas = 20_000u64;
    let total_reserved = initial_gas + extra_gas;
    let max_gas = 150_000u64;
    let code = format!(r#"
        pub fn callback() -> u64 {{
            return 0
        }}

        entry main() {{
            let execution = ScheduledExecution::new_at_block_end(callback, [], {initial_gas}u64, false)
                .expect("scheduled execution");
            require(execution.increase_max_gas({extra_gas}u64, false), "gas increase must succeed");
            require(false, "fail after increasing scheduled gas");
            return 0
        }}
    "#);

    let mut chain_state = MockChainState::new();
    let contract = create_contract(&mut chain_state, &code, ContractVersion::V1)
        .expect("create contract");

    let source = KeyPair::new().get_public_key().compress();
    let result = vm::invoke_contract(
        ContractCaller::Impersonate(Cow::Owned(source)),
        &mut chain_state,
        Cow::Owned(contract),
        None,
        std::iter::empty(),
        IndexMap::new(),
        max_gas,
        InvokeContract::Entry(1),
        Cow::Owned(Default::default()),
        true,
    ).await
        .expect("invoke scheduler");

    assert!(!result.is_success(), "contract must fail after increasing scheduled gas");
    assert!(chain_state.executions.block_end.is_empty(), "failed execution must not commit block-end pointer");
    assert!(chain_state.executions.executions.is_empty(), "failed execution must not commit scheduled execution");

    let refund = refund_gas_amount(&chain_state, &Hash::zero());
    assert!(
        refund > max_gas - total_reserved,
        "discarded scheduled gas allowance, including increase, should be refundable on failure"
    );
}

#[tokio::test]
async fn contract_paid_scheduled_execution_increase_over_limit_rolls_back() {
    let initial_gas = MAX_GAS_USAGE_PER_TX - 1;
    let initial_balance = initial_gas + COST_PER_SCHEDULED_EXECUTION_AT_BLOCK_END + 1_000;
    let code = format!(r#"
        pub fn callback() -> u64 {{
            return 0
        }}

        entry main() {{
            let execution = ScheduledExecution::new_at_block_end(callback, [], {initial_gas}u64, true)
                .expect("scheduled execution");
            execution.increase_max_gas(2u64, true);
            return 0
        }}
    "#);

    let mut chain_state = MockChainState::with(BlockVersion::V6);
    let contract = create_contract(&mut chain_state, &code, ContractVersion::V1)
        .expect("create contract");
    chain_state.set_contract_balance(&contract, &XELIS_ASSET, initial_balance);

    let result = vm::invoke_contract(
        ContractCaller::System,
        &mut chain_state,
        Cow::Owned(contract.clone()),
        None,
        std::iter::empty(),
        IndexMap::new(),
        MAX_GAS_USAGE_PER_TX,
        InvokeContract::Entry(1),
        Cow::Owned(Default::default()),
        true,
    ).await
        .expect("invoke scheduler");

    assert!(!result.is_success(), "over-limit increase must fail the contract");
    assert_eq!(
        chain_state.get_contract_balance(&contract, &XELIS_ASSET),
        initial_balance,
        "failed over-limit increase must not charge contract balance"
    );
    assert!(chain_state.executions.block_end.is_empty(), "failed over-limit increase must not commit pointer");
    assert!(chain_state.executions.executions.is_empty(), "failed over-limit increase must not commit execution");
}

#[tokio::test]
async fn successful_account_paid_event_listener_keeps_callback_gas_funded() {
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
        pub fn on_event(args: any[]) -> u64 {
            return 0
        }

        entry main() {
            let emitter: Hash = Hash::from_hex("EMITTER_HASH");
            let contract = Contract::new(emitter).expect("load emitter");
            let registered = contract.listen_event(7, on_event, 50000u64);
            require(registered, "event listener was not registered");
            return 0
        }
    "#.replace("EMITTER_HASH", &emitter.to_string());

    let listener = create_contract(&mut chain_state, &listener_code, ContractVersion::V1)
        .expect("create listener");
    let source = KeyPair::new().get_public_key().compress();
    let max_gas = 100000u64;

    let result = vm::invoke_contract(
        ContractCaller::Impersonate(Cow::Owned(source)),
        &mut chain_state,
        Cow::Owned(listener),
        None,
        std::iter::empty(),
        IndexMap::new(),
        max_gas,
        InvokeContract::Entry(1),
        Cow::Owned(Default::default()),
        true,
    ).await
        .expect("invoke listener");

    assert!(result.is_success(), "listener registration should succeed: {:?}", result);
    assert_eq!(
        chain_state.events_listeners.get(&(emitter, 7)).map(Vec::len),
        Some(1),
        "event listener must be registered"
    );

    let synthetic_caller = Hash::zero();
    let refund = refund_gas_amount(&chain_state, &synthetic_caller);
    assert!(
        refund <= max_gas - 50000,
        "outer refund must not include gas reserved for the future event callback"
    );
}

#[tokio::test]
async fn failed_account_paid_event_listener_refunds_only_current_input() {
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
        pub fn on_event(args: any[]) -> u64 {
            return 0
        }

        entry main() {
            let emitter: Hash = Hash::from_hex("EMITTER_HASH");
            let contract = Contract::new(emitter).expect("load emitter");
            let registered = contract.listen_event(7, on_event, 50000u64);
            require(registered, "event listener was not registered");
            require(false, "fail after reserving callback gas");
            return 0
        }
    "#.replace("EMITTER_HASH", &emitter.to_string());

    let listener = create_contract(&mut chain_state, &listener_code, ContractVersion::V1)
        .expect("create listener");
    let source = KeyPair::new().get_public_key().compress();
    let max_gas = 100000u64;

    let result = vm::invoke_contract(
        ContractCaller::Impersonate(Cow::Owned(source)),
        &mut chain_state,
        Cow::Owned(listener),
        None,
        std::iter::empty(),
        IndexMap::new(),
        max_gas,
        InvokeContract::Entry(1),
        Cow::Owned(Default::default()),
        true,
    ).await
        .expect("invoke listener");

    assert!(!result.is_success(), "listener registration must fail after the forced error");
    assert!(
        chain_state.events_listeners.is_empty(),
        "failed execution must not commit the event listener"
    );

    let synthetic_caller = Hash::zero();
    let refund = refund_gas_amount(&chain_state, &synthetic_caller);
    assert!(
        refund <= max_gas,
        "failed execution refund must never exceed the original tx gas input"
    );
    assert!(
        refund > max_gas - 50000,
        "discarded event callback gas allowance should be refundable on failure"
    );
}

#[tokio::test]
async fn fired_event_callback_pays_fee_and_refunds_only_leftover_to_listener_contract() {
    let callback_gas = 50000u64;
    let emitter_code = r#"
        entry emit() -> u64 {
            emit_event(7, []);
            return 0
        }
    "#;

    let mut chain_state = MockChainState::new();
    let emitter = create_contract(&mut chain_state, emitter_code, ContractVersion::V1)
        .expect("create emitter");

    let listener_code = format!(r#"
        pub fn on_event() -> u64 {{
            return 0
        }}

        entry main() {{
            let emitter: Hash = Hash::from_hex("EMITTER_HASH");
            let contract = Contract::new(emitter).expect("load emitter");
            let registered = contract.listen_event(7, on_event, {callback_gas}u64);
            require(registered, "event listener was not registered");
            return 0
        }}
    "#).replace("EMITTER_HASH", &emitter.to_string());

    let listener = create_contract(&mut chain_state, &listener_code, ContractVersion::V1)
        .expect("create listener");
    let source = KeyPair::new().get_public_key().compress();

    let registration = vm::invoke_contract(
        ContractCaller::Impersonate(Cow::Owned(source)),
        &mut chain_state,
        Cow::Owned(listener.clone()),
        None,
        std::iter::empty(),
        IndexMap::new(),
        100000,
        InvokeContract::Entry(1),
        Cow::Owned(Default::default()),
        true,
    ).await
        .expect("register event listener");

    assert!(
        registration.is_success(),
        "listener registration should succeed: {:?}",
        registration
    );
    assert_eq!(
        chain_state.events_listeners.get(&(emitter.clone(), 7)).map(Vec::len),
        Some(1),
        "event listener must be registered before firing event"
    );

    let emit = vm::invoke_contract(
        ContractCaller::System,
        &mut chain_state,
        Cow::Owned(emitter),
        None,
        std::iter::empty(),
        IndexMap::new(),
        100000,
        InvokeContract::Entry(0),
        Cow::Owned(Default::default()),
        false,
    ).await
        .expect("emit event without post hook");

    assert!(emit.is_success(), "event emitter should succeed: {:?}", emit);
    assert_eq!(chain_state.events.len(), 1, "event should be queued");

    let gas_fee_before = chain_state.gas_fee;
    let burned_fee_before = chain_state.burned_fee;
    chain_state.on_post_execution(&Hash::zero()).await
        .expect("process event callback");

    assert!(
        chain_state.events.is_empty(),
        "event queue should be drained after callback"
    );
    assert!(
        chain_state.events_listeners.is_empty(),
        "listener should be consumed after event callback"
    );

    let callback_used_gas = chain_state.gas_fee - gas_fee_before
        + chain_state.burned_fee - burned_fee_before;
    assert!(
        callback_used_gas < callback_gas,
        "event callback should leave gas to refund"
    );

    assert_contract_gas_conservation(
        &mut chain_state,
        &listener,
        callback_gas,
        callback_used_gas,
        gas_fee_before,
        burned_fee_before,
    ).await;
}

#[tokio::test]
async fn test_refund_gas_sources_single_contract() {
    let mut state = MockChainState::new();
    let contract_hash = Hash::zero();
    
    // Initialize contract with balance
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract_hash).await.unwrap();
        *balance = 1000;
    }
    
    // Create gas sources - contract injected 1000 gas
    let mut gas_sources = IndexMap::new();
    gas_sources.insert(Source::Contract(contract_hash.clone()), 1000);
    
    // Used gas: 600, max gas: 1000
    // Should refund: 1000 - 600 = 400
    refund_gas_sources(&mut state, gas_sources, 600, 1000).await.unwrap();
    
    // Check contract balance was refunded
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract_hash).await.unwrap();
        assert_eq!(*balance, 1400); // 1000 + 400 refund
    }
}

#[tokio::test]
async fn test_refund_gas_sources_single_account() {
    let mut state = MockChainState::new();
    let keypair = KeyPair::new();
    let account = keypair.get_public_key().compress();
    
    // Initialize account with balance (encrypted)
    {
        let balance_ct = keypair.get_public_key().encrypt(2000u64);
        state.accounts.insert(account.clone(), MockAccount {
            balances: [(XELIS_ASSET, balance_ct)].into_iter().collect(),
            nonce: 0,
        });
    }
    
    // Create gas sources - account paid 500 gas
    let mut gas_sources = IndexMap::new();
    gas_sources.insert(Source::Account(account.clone()), 500);
    
    // Used gas: 300, max gas: 500
    // Should refund: 500 - 300 = 200
    refund_gas_sources(&mut state, gas_sources, 300, 500).await.unwrap();
    
    // Check account balance was refunded (should add 200 to the ciphertext)
    let balance_ct = &state.accounts.get(&account).unwrap().balances[&XELIS_ASSET];
    let decrypted = keypair.decrypt_to_point(balance_ct);
    assert_eq!(decrypted, Scalar::from(2200u64) * (*G)); // 2000 + 200 refund
}

#[tokio::test]
async fn test_refund_gas_sources_multiple_contracts() {
    let mut state = MockChainState::new();
    let contract1 = Hash::zero();
    let contract2 = Hash::new([1u8; 32]);
    
    // Initialize contracts with balances
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract1).await.unwrap();
        *balance = 500;
    }
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract2).await.unwrap();
        *balance = 800;
    }
    
    // Create gas sources
    // contract1 injected 200 gas, contract2 injected 200 gas
    // Total: 400 gas
    let mut gas_sources = IndexMap::new();
    gas_sources.insert(Source::Contract(contract1.clone()), 200);
    gas_sources.insert(Source::Contract(contract2.clone()), 200);
    
    // Used gas: 300, max gas: 400
    // Should refund: 400 - 300 = 100
    // Each contract should get proportional refund: 50 each (100 * 200/400)
    refund_gas_sources(&mut state, gas_sources, 300, 400).await.unwrap();
    
    // Check balances
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract1).await.unwrap();
        assert_eq!(*balance, 550); // 500 + 50 refund
    }
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract2).await.unwrap();
        assert_eq!(*balance, 850); // 800 + 50 refund
    }
}

#[tokio::test]
async fn test_refund_gas_sources_proportional_different_amounts() {
    let mut state = MockChainState::new();
    let contract1 = Hash::zero();
    let contract2 = Hash::new([1u8; 32]);
    
    // Initialize contracts with balances
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract1).await.unwrap();
        *balance = 1000;
    }
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract2).await.unwrap();
        *balance = 2000;
    }
    
    // Create gas sources
    // contract1 injected 300 gas, contract2 injected 700 gas
    // Total: 1000 gas
    let mut gas_sources = IndexMap::new();
    gas_sources.insert(Source::Contract(contract1.clone()), 300);
    gas_sources.insert(Source::Contract(contract2.clone()), 700);
    
    // Used gas: 600, max gas: 1000
    // Should refund: 1000 - 600 = 400
    // contract1 should get: 400 * 300/1000 = 120
    // contract2 should get: 400 * 700/1000 = 280
    refund_gas_sources(&mut state, gas_sources, 600, 1000).await.unwrap();
    
    // Check balances
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract1).await.unwrap();
        assert_eq!(*balance, 1120); // 1000 + 120 refund
    }
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract2).await.unwrap();
        assert_eq!(*balance, 2280); // 2000 + 280 refund
    }
}

#[tokio::test]
async fn test_refund_gas_sources_all_gas_used() {
    let mut state = MockChainState::new();
    let contract = Hash::zero();
    
    // Initialize contract with balance
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract).await.unwrap();
        *balance = 1000;
    }
    
    // Create gas sources - contract injected 500 gas
    let mut gas_sources = IndexMap::new();
    gas_sources.insert(Source::Contract(contract.clone()), 500);
    
    // Used gas: 500, max gas: 500
    // Should refund: 0 (all gas was used)
    refund_gas_sources(&mut state, gas_sources, 500, 500).await.unwrap();
    
    // Check contract balance - should be unchanged
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract).await.unwrap();
        assert_eq!(*balance, 1000); // No refund
    }
}

#[tokio::test]
async fn test_refund_gas_sources_no_overflow() {
    let mut state = MockChainState::new();
    let contract = Hash::zero();
    
    // Initialize contract with balance
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract).await.unwrap();
        *balance = 5000;
    }
    
    // Create gas sources - contract injected 1000 gas
    let mut gas_sources = IndexMap::new();
    gas_sources.insert(Source::Contract(contract.clone()), 1000);
    
    // Used gas can exceed reserved gas when extra gas was paid by runtime
    // injections. There is no reserved gas left to refund, but this must not
    // overflow.
    refund_gas_sources(&mut state, gas_sources, 1200, 1000).await.unwrap();

    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract).await.unwrap();
        assert_eq!(*balance, 5000);
    }
}

#[tokio::test]
async fn test_refund_gas_sources_mixed_sources() {
    let mut state = MockChainState::new();
    let contract = Hash::zero();
    let keypair = KeyPair::new();
    let account = keypair.get_public_key().compress();
    
    // Initialize contract with balance
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract).await.unwrap();
        *balance = 3000;
    }
    
    // Initialize account with balance
    {
        let balance_ct = keypair.get_public_key().encrypt(5000u64);
        state.accounts.insert(account.clone(), MockAccount {
            balances: [(XELIS_ASSET, balance_ct)].into_iter().collect(),
            nonce: 0,
        });
    }
    
    // Create gas sources
    // contract injected 600 gas, account paid 400 gas
    // Total: 1000 gas
    let mut gas_sources = IndexMap::new();
    gas_sources.insert(Source::Contract(contract.clone()), 600);
    gas_sources.insert(Source::Account(account.clone()), 400);
    
    // Used gas: 700, max gas: 1000
    // Should refund: 1000 - 700 = 300
    // contract should get: 300 * 600/1000 = 180
    // account should get: 300 * 400/1000 = 120
    refund_gas_sources(&mut state, gas_sources, 700, 1000).await.unwrap();
    
    // Check contract balance
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract).await.unwrap();
        assert_eq!(*balance, 3180); // 3000 + 180 refund
    }
    
    // Check account balance
    let balance_ct = &state.accounts.get(&account).unwrap().balances[&XELIS_ASSET];
    let balance_point = keypair.decrypt_to_point(balance_ct);

    assert_eq!(balance_point, Scalar::from(5120u64) * (*G)); // 5000 + 120 refund
}

#[tokio::test]
async fn test_refund_gas_sources_rounding_remainder_conserves_and_pays_only_sources() {
    let mut state = MockChainState::new();
    let contract1 = Hash::zero();
    let contract2 = Hash::new([1u8; 32]);
    let keypair = KeyPair::new();
    let account = keypair.get_public_key().compress();
    let bystander = KeyPair::new();
    let bystander_account = bystander.get_public_key().compress();

    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract1).await.unwrap();
        *balance = 1000;
    }
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract2).await.unwrap();
        *balance = 2000;
    }

    state.accounts.insert(account.clone(), MockAccount {
        balances: [(XELIS_ASSET, keypair.get_public_key().encrypt(3000u64))]
            .into_iter()
            .collect(),
        nonce: 0,
    });
    state.accounts.insert(bystander_account.clone(), MockAccount {
        balances: [(XELIS_ASSET, bystander.get_public_key().encrypt(4000u64))]
            .into_iter()
            .collect(),
        nonce: 0,
    });

    let mut gas_sources = IndexMap::new();
    gas_sources.insert(Source::Contract(contract1.clone()), 2);
    gas_sources.insert(Source::Contract(contract2.clone()), 3);
    gas_sources.insert(Source::Account(account.clone()), 5);

    refund_gas_sources(&mut state, gas_sources, 2, 10).await.unwrap();

    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract1).await.unwrap();
        assert_eq!(*balance, 1002, "first contract receives the deterministic rounding remainder");
    }
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract2).await.unwrap();
        assert_eq!(*balance, 2002, "second contract receives only its proportional refund");
    }
    assert_account_xelis_balance(
        &state,
        &keypair,
        &account,
        3004,
        "account source receives only its proportional refund"
    );
    assert_account_xelis_balance(
        &state,
        &bystander,
        &bystander_account,
        4000,
        "non-source account must not receive gas refund"
    );

    let refunded = (1002 - 1000) + (2002 - 2000) + (3004 - 3000);
    assert_eq!(refunded, 8, "all unused funded gas must be refunded exactly once");
    assert_eq!(state.gas_fee, 0, "refund helper must not mint miner fees");
    assert_eq!(state.burned_fee, 0, "refund helper must not mint burned fees");
}

#[tokio::test]
async fn test_refund_gas_sources_empty_sources() {
    let mut state = MockChainState::new();
    
    // Empty gas sources are valid only for a zero max-gas source set.
    let gas_sources = IndexMap::new();
    
    refund_gas_sources(&mut state, gas_sources, 0, 0).await.unwrap();
    
    // Nothing should have changed
    assert!(state.contract_caches.is_empty());
}

#[tokio::test]
async fn test_refund_gas_sources_rejects_max_gas_above_total_sources() {
    let mut state = MockChainState::new();
    let contract = Hash::zero();

    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract).await.unwrap();
        *balance = 1000;
    }

    let mut gas_sources = IndexMap::new();
    gas_sources.insert(Source::Contract(contract.clone()), 100);

    let result = refund_gas_sources(&mut state, gas_sources, 0, 1000).await;
    assert!(result.is_err(), "max gas must match the sum of all gas sources");

    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract).await.unwrap();
        assert_eq!(
            *balance,
            1000,
            "rejected mismatch must not mutate contract balance"
        );
    }
}

#[tokio::test]
async fn test_refund_gas_sources_mixed_source_max_gas_mismatch() {
    let mut state = MockChainState::new();
    let contract = Hash::zero();
    let keypair = KeyPair::new();
    let account = keypair.get_public_key().compress();


    {
        let balance_ct = keypair.get_public_key().encrypt(2000u64);
        state.accounts.insert(account.clone(), MockAccount {
            balances: [(XELIS_ASSET, balance_ct)].into_iter().collect(),
            nonce: 0,
        });
    }

    let mut gas_sources = IndexMap::new();
    gas_sources.insert(Source::Contract(contract.clone()), 950);
    gas_sources.insert(Source::Account(account.clone()), 50);

    refund_gas_sources(&mut state, gas_sources, 0, 1000).await.unwrap();

    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract).await.unwrap();
        assert_eq!(*balance, 950, "rejected mismatch must not mutate contract balance");
    }

    let balance_ct = &state.accounts.get(&account).unwrap().balances[&XELIS_ASSET];
    let balance_point = keypair.decrypt_to_point(balance_ct);
    assert_eq!(
        balance_point,
        Scalar::from(2050u64) * (*G),
        "rejected mismatch must not mutate account balance"
    );
}

#[tokio::test]
async fn test_refund_gas_sources_rejects_total_input_overflow_without_outputs() {
    let mut state = MockChainState::new();
    let contract1 = Hash::zero();
    let contract2 = Hash::new([1u8; 32]);

    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract1).await.unwrap();
        *balance = 1000;
    }
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract2).await.unwrap();
        *balance = 2000;
    }

    let mut gas_sources = IndexMap::new();
    gas_sources.insert(Source::Contract(contract1.clone()), u64::MAX);
    gas_sources.insert(Source::Contract(contract2.clone()), 1);

    let result = refund_gas_sources(&mut state, gas_sources, 0, u64::MAX).await;
    assert!(result.is_err(), "overflowing source sum must be rejected");

    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract1).await.unwrap();
        assert_eq!(*balance, 1000, "first contract balance must remain unchanged");
    }
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract2).await.unwrap();
        assert_eq!(*balance, 2000, "second contract balance must remain unchanged");
    }
}

#[tokio::test]
async fn test_refund_gas_sources_rejects_contract_balance_overflow_without_output() {
    let mut state = MockChainState::new();
    let contract = Hash::zero();

    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract).await.unwrap();
        *balance = u64::MAX;
    }

    let mut gas_sources = IndexMap::new();
    gas_sources.insert(Source::Contract(contract.clone()), 1);

    let result = refund_gas_sources(&mut state, gas_sources, 0, 1).await;
    assert!(result.is_err(), "overflowing contract refund must be rejected");

    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract).await.unwrap();
        assert_eq!(
            *balance,
            u64::MAX,
            "failed refund must not mutate contract balance"
        );
    }
}

#[tokio::test]
async fn test_refund_gas_sources_late_contract_overflow_does_not_partially_refund() {
    let mut state = MockChainState::new();
    let first = Hash::zero();
    let second = Hash::new([1u8; 32]);

    {
        let (_, balance) = state.get_contract_balance_for_gas(&first).await.unwrap();
        *balance = 1000;
    }
    {
        let (_, balance) = state.get_contract_balance_for_gas(&second).await.unwrap();
        *balance = u64::MAX;
    }

    let mut gas_sources = IndexMap::new();
    gas_sources.insert(Source::Contract(first.clone()), 50);
    gas_sources.insert(Source::Contract(second.clone()), 50);

    let result = refund_gas_sources(&mut state, gas_sources, 0, 100).await;
    assert!(result.is_err(), "late balance overflow must reject all refunds");

    {
        let (_, balance) = state.get_contract_balance_for_gas(&first).await.unwrap();
        assert_eq!(*balance, 1000, "first source must not be partially refunded");
    }
    {
        let (_, balance) = state.get_contract_balance_for_gas(&second).await.unwrap();
        assert_eq!(*balance, u64::MAX, "overflowing source must remain unchanged");
    }
}

#[tokio::test]
async fn test_refund_gas_sources_late_missing_account_does_not_partially_refund() {
    let mut state = MockChainState::new();
    let contract = Hash::zero();
    let missing_account = KeyPair::new().get_public_key().compress();

    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract).await.unwrap();
        *balance = 1000;
    }

    let mut gas_sources = IndexMap::new();
    gas_sources.insert(Source::Contract(contract.clone()), 50);
    gas_sources.insert(Source::Account(missing_account), 50);

    let result = refund_gas_sources(&mut state, gas_sources, 0, 100).await;
    assert!(result.is_err(), "late missing account must reject all refunds");

    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract).await.unwrap();
        assert_eq!(*balance, 1000, "contract must not be partially refunded");
    }
}

#[tokio::test]
async fn test_refund_gas_sources_zero_amount_source_does_not_receive_refund() {
    let mut state = MockChainState::new();
    let zero_contract = Hash::zero();
    let funded_contract = Hash::new([1u8; 32]);

    {
        let (_, balance) = state.get_contract_balance_for_gas(&zero_contract).await.unwrap();
        *balance = 1000;
    }
    {
        let (_, balance) = state.get_contract_balance_for_gas(&funded_contract).await.unwrap();
        *balance = 2000;
    }

    let mut gas_sources = IndexMap::new();
    gas_sources.insert(Source::Contract(zero_contract.clone()), 0);
    gas_sources.insert(Source::Contract(funded_contract.clone()), 100);

    refund_gas_sources(&mut state, gas_sources, 25, 100).await.unwrap();

    {
        let (_, balance) = state.get_contract_balance_for_gas(&zero_contract).await.unwrap();
        assert_eq!(*balance, 1000, "zero source must not receive refund");
    }
    {
        let (_, balance) = state.get_contract_balance_for_gas(&funded_contract).await.unwrap();
        assert_eq!(*balance, 2075, "funded source receives only remaining funded gas");
    }
}

#[tokio::test]
async fn test_refund_gas_sources_rounding_dust_does_not_over_refund() {
    let mut state = MockChainState::new();
    let contract1 = Hash::zero();
    let contract2 = Hash::new([1u8; 32]);
    let contract3 = Hash::new([2u8; 32]);

    for contract in [&contract1, &contract2, &contract3] {
        let (_, balance) = state.get_contract_balance_for_gas(contract).await.unwrap();
        *balance = 1000;
    }

    let mut gas_sources = IndexMap::new();
    gas_sources.insert(Source::Contract(contract1.clone()), 1);
    gas_sources.insert(Source::Contract(contract2.clone()), 1);
    gas_sources.insert(Source::Contract(contract3.clone()), 1);

    refund_gas_sources(&mut state, gas_sources, 2, 3).await.unwrap();

    let mut total_refunded = 0u64;
    for contract in [&contract1, &contract2, &contract3] {
        let (_, balance) = state.get_contract_balance_for_gas(contract).await.unwrap();
        let refunded = *balance - 1000;
        assert!(refunded <= 1, "single source must not receive more than it injected");
        total_refunded += refunded;
    }

    assert!(
        total_refunded == 1,
        "rounding remainder must be refunded exactly once"
    );
}

#[tokio::test]
async fn test_refund_extra_gas_injections_refunds_latest_sources_first() {
    let mut state = MockChainState::new();
    let first = Hash::zero();
    let second = Hash::new([1u8; 32]);
    let mut caches = std::collections::HashMap::new();

    for contract in [&first, &second] {
        let mut cache = ContractCache::default();
        cache.balances.insert(
            XELIS_ASSET,
            Some((VersionedState::New, 0))
        );
        caches.insert(contract.clone(), cache);
    }

    let mut gas_injections = IndexMap::new();
    gas_injections.insert(Source::Contract(first.clone()), 100);
    gas_injections.insert(Source::Contract(second.clone()), 50);
    let mut outputs = Vec::new();

    vm::refund_extra_gas_injections(
        &mut state,
        gas_injections,
        100,
        130,
        250,
        &mut outputs,
        &mut caches,
    ).await
        .expect("refund extra gas injections");

    let first_balance = caches[&first].balances[&XELIS_ASSET].as_ref().unwrap().1;
    let second_balance = caches[&second].balances[&XELIS_ASSET].as_ref().unwrap().1;
    assert_eq!(second_balance, 50, "latest source should be refunded first");
    assert_eq!(first_balance, 70, "older source receives remaining refund");
    assert_eq!(outputs.len(), 1, "only consumed gas should be logged");
    assert_gas_injection_log(&outputs[0], &first, 30);
}

#[tokio::test]
async fn test_refund_extra_gas_injections_all_unused_refunds_all_sources_without_logs() {
    let mut state = MockChainState::new();
    let first = Hash::zero();
    let second = Hash::new([1u8; 32]);
    let mut caches = std::collections::HashMap::new();

    for contract in [&first, &second] {
        let mut cache = ContractCache::default();
        cache.balances.insert(
            XELIS_ASSET,
            Some((VersionedState::New, 0))
        );
        caches.insert(contract.clone(), cache);
    }

    let mut gas_injections = IndexMap::new();
    gas_injections.insert(Source::Contract(first.clone()), 100);
    gas_injections.insert(Source::Contract(second.clone()), 50);
    let mut outputs = Vec::new();

    vm::refund_extra_gas_injections(
        &mut state,
        gas_injections,
        100,
        80,
        250,
        &mut outputs,
        &mut caches,
    ).await
        .expect("refund extra gas injections");

    assert_eq!(
        caches[&first].balances[&XELIS_ASSET].as_ref().unwrap().1,
        100,
        "first source must receive its full unused injection"
    );
    assert_eq!(
        caches[&second].balances[&XELIS_ASSET].as_ref().unwrap().1,
        50,
        "second source must receive its full unused injection"
    );
    assert!(outputs.is_empty(), "fully refunded injections must not be logged as consumed");
}

#[tokio::test]
async fn test_refund_extra_gas_injections_all_consumed_refunds_nothing_and_logs_sources() {
    let mut state = MockChainState::new();
    let first = Hash::zero();
    let second = Hash::new([1u8; 32]);
    let mut caches = std::collections::HashMap::new();

    for contract in [&first, &second] {
        let mut cache = ContractCache::default();
        cache.balances.insert(
            XELIS_ASSET,
            Some((VersionedState::New, 0))
        );
        caches.insert(contract.clone(), cache);
    }

    let mut gas_injections = IndexMap::new();
    gas_injections.insert(Source::Contract(first.clone()), 100);
    gas_injections.insert(Source::Contract(second.clone()), 50);
    let mut outputs = Vec::new();

    vm::refund_extra_gas_injections(
        &mut state,
        gas_injections,
        100,
        250,
        250,
        &mut outputs,
        &mut caches,
    ).await
        .expect("refund extra gas injections");

    assert_eq!(caches[&first].balances[&XELIS_ASSET].as_ref().unwrap().1, 0);
    assert_eq!(caches[&second].balances[&XELIS_ASSET].as_ref().unwrap().1, 0);
    assert_eq!(outputs.len(), 2, "all consumed injections must be logged");
    assert_gas_injection_log(&outputs[0], &second, 50);
    assert_gas_injection_log(&outputs[1], &first, 100);
}

#[tokio::test]
async fn test_refund_extra_gas_injections_mixed_account_contract_pays_correct_sources() {
    let mut state = MockChainState::new();
    let contract = Hash::zero();
    let keypair = KeyPair::new();
    let account = keypair.get_public_key().compress();
    let bystander = KeyPair::new();
    let bystander_account = bystander.get_public_key().compress();
    let mut caches = std::collections::HashMap::new();

    let mut cache = ContractCache::default();
    cache.balances.insert(
        XELIS_ASSET,
        Some((VersionedState::New, 0))
    );
    caches.insert(contract.clone(), cache);

    state.accounts.insert(account.clone(), MockAccount {
        balances: [(XELIS_ASSET, keypair.get_public_key().encrypt(500u64))]
            .into_iter()
            .collect(),
        nonce: 0,
    });
    state.accounts.insert(bystander_account.clone(), MockAccount {
        balances: [(XELIS_ASSET, bystander.get_public_key().encrypt(700u64))]
            .into_iter()
            .collect(),
        nonce: 0,
    });

    let mut gas_injections = IndexMap::new();
    gas_injections.insert(Source::Contract(contract.clone()), 100);
    gas_injections.insert(Source::Account(account.clone()), 50);
    let mut outputs = Vec::new();

    vm::refund_extra_gas_injections(
        &mut state,
        gas_injections,
        100,
        130,
        250,
        &mut outputs,
        &mut caches,
    ).await
        .expect("refund extra gas injections");

    assert_eq!(
        caches[&contract].balances[&XELIS_ASSET].as_ref().unwrap().1,
        70,
        "contract source receives only its unused part"
    );
    assert_account_xelis_balance(
        &state,
        &keypair,
        &account,
        550,
        "account source receives its full unused part"
    );
    assert_account_xelis_balance(
        &state,
        &bystander,
        &bystander_account,
        700,
        "non-source account must not receive extra gas refund"
    );
    assert_eq!(outputs.len(), 1, "only consumed contract gas should be logged");
    assert_gas_injection_log(&outputs[0], &contract, 30);

    let refunded = 70 + (550 - 500);
    let consumed = 30;
    assert_eq!(
        refunded + consumed,
        150,
        "contract and account gas injections must be conserved"
    );
}

#[tokio::test]
async fn test_refund_extra_gas_injections_rejects_missing_cache_without_outputs() {
    let mut state = MockChainState::new();
    let contract = Hash::zero();
    let mut gas_injections = IndexMap::new();
    gas_injections.insert(Source::Contract(contract), 100);
    let mut outputs = Vec::new();
    let mut caches = std::collections::HashMap::new();

    let result = vm::refund_extra_gas_injections(
        &mut state,
        gas_injections,
        100,
        100,
        150,
        &mut outputs,
        &mut caches,
    ).await;

    assert!(result.is_err(), "missing cache must reject refund");
    assert!(outputs.is_empty(), "failed refund must not add outputs");
}

#[tokio::test]
async fn test_refund_extra_gas_injections_late_missing_cache_does_not_partially_refund() {
    let mut state = MockChainState::new();
    let first = Hash::zero();
    let missing = Hash::new([1u8; 32]);
    let mut cache = ContractCache::default();
    cache.balances.insert(
        XELIS_ASSET,
        Some((VersionedState::New, 1000))
    );
    let mut caches = [(first.clone(), cache)].into_iter().collect();
    let mut gas_injections = IndexMap::new();
    gas_injections.insert(Source::Contract(missing), 50);
    gas_injections.insert(Source::Contract(first.clone()), 50);
    let mut outputs = Vec::new();

    let result = vm::refund_extra_gas_injections(
        &mut state,
        gas_injections,
        100,
        100,
        200,
        &mut outputs,
        &mut caches,
    ).await;

    assert!(result.is_err(), "late missing cache must reject all refunds");
    assert_eq!(
        caches[&first].balances[&XELIS_ASSET].as_ref().unwrap().1,
        1000,
        "first source must not be partially refunded"
    );
    assert!(outputs.is_empty(), "failed refund must not add outputs");
}

#[tokio::test]
async fn test_refund_extra_gas_injections_late_overflow_does_not_partially_refund() {
    let mut state = MockChainState::new();
    let first = Hash::zero();
    let overflowing = Hash::new([1u8; 32]);
    let mut caches = std::collections::HashMap::new();

    let mut first_cache = ContractCache::default();
    first_cache.balances.insert(
        XELIS_ASSET,
        Some((VersionedState::New, 1000))
    );
    caches.insert(first.clone(), first_cache);

    let mut overflowing_cache = ContractCache::default();
    overflowing_cache.balances.insert(
        XELIS_ASSET,
        Some((VersionedState::New, u64::MAX))
    );
    caches.insert(overflowing.clone(), overflowing_cache);

    let mut gas_injections = IndexMap::new();
    gas_injections.insert(Source::Contract(overflowing.clone()), 50);
    gas_injections.insert(Source::Contract(first.clone()), 50);
    let mut outputs = Vec::new();

    let result = vm::refund_extra_gas_injections(
        &mut state,
        gas_injections,
        100,
        100,
        200,
        &mut outputs,
        &mut caches,
    ).await;

    assert!(result.is_err(), "late overflow must reject all refunds");
    assert_eq!(
        caches[&first].balances[&XELIS_ASSET].as_ref().unwrap().1,
        1000,
        "first source must not be partially refunded"
    );
    assert_eq!(
        caches[&overflowing].balances[&XELIS_ASSET].as_ref().unwrap().1,
        u64::MAX,
        "overflowing source must remain unchanged"
    );
    assert!(outputs.is_empty(), "failed refund must not add outputs");
}

#[tokio::test]
async fn test_charge_gas_injections_consumes_in_order_and_logs_only_consumed() {
    let mut state = MockChainState::new();
    let first = Hash::zero();
    let second = Hash::new([1u8; 32]);

    {
        let (_, balance) = state.get_contract_balance_for_gas(&first).await.unwrap();
        *balance = 1000;
    }
    {
        let (_, balance) = state.get_contract_balance_for_gas(&second).await.unwrap();
        *balance = 2000;
    }

    let mut gas_injections = IndexMap::new();
    gas_injections.insert(Source::Contract(first.clone()), 100);
    gas_injections.insert(Source::Contract(second.clone()), 100);
    let mut outputs = Vec::new();

    vm::charge_gas_injections(
        &mut state,
        gas_injections,
        150,
        &mut outputs,
    ).await
        .expect("charge gas injections");

    {
        let (_, balance) = state.get_contract_balance_for_gas(&first).await.unwrap();
        assert_eq!(*balance, 900, "first source should be consumed first");
    }
    {
        let (_, balance) = state.get_contract_balance_for_gas(&second).await.unwrap();
        assert_eq!(*balance, 1950, "second source should cover remaining gas");
    }
    assert_eq!(outputs.len(), 2, "only consumed amounts should be logged");
    assert_gas_injection_log(&outputs[0], &first, 100);
    assert_gas_injection_log(&outputs[1], &second, 50);
}

#[tokio::test]
async fn test_charge_gas_injections_rejects_account_source_without_mutating_contracts() {
    let mut state = MockChainState::new();
    let contract = Hash::zero();
    let keypair = KeyPair::new();
    let account = keypair.get_public_key().compress();

    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract).await.unwrap();
        *balance = 1000;
    }

    let mut gas_injections = IndexMap::new();
    gas_injections.insert(Source::Account(account), 50);
    gas_injections.insert(Source::Contract(contract.clone()), 50);
    let mut outputs = Vec::new();

    let result = vm::charge_gas_injections(
        &mut state,
        gas_injections,
        25,
        &mut outputs,
    ).await;

    assert!(result.is_err(), "account gas injection consumption must be rejected");
    assert!(outputs.is_empty(), "failed charge must not log consumed gas");
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract).await.unwrap();
        assert_eq!(*balance, 1000, "contract balance must remain unchanged");
    }
}

#[tokio::test]
async fn test_charge_gas_injections_rejects_insufficient_sources() {
    let mut state = MockChainState::new();
    let contract = Hash::zero();

    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract).await.unwrap();
        *balance = 1000;
    }

    let mut gas_injections = IndexMap::new();
    gas_injections.insert(Source::Contract(contract.clone()), 50);
    let mut outputs = Vec::new();

    let result = vm::charge_gas_injections(
        &mut state,
        gas_injections,
        75,
        &mut outputs,
    ).await;

    assert!(result.is_err(), "insufficient gas injections must be rejected");
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract).await.unwrap();
        assert_eq!(
            *balance,
            1000,
            "insufficient charge must not partially mutate contract balance"
        );
    }
    assert!(outputs.is_empty(), "insufficient charge must not log consumed gas");
}
