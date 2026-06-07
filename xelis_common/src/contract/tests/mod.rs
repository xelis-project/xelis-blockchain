use std::{borrow::Cow, sync::Arc};
use indexmap::IndexMap;

use xelis_builder::EnvironmentBuilder;
use xelis_compiler::Compiler;
use xelis_lexer::Lexer;
use xelis_parser::Parser;
use xelis_vm::{Module, Primitive, ValueCell};

use crate::{
    asset::{AssetData, AssetOwner, MaxSupplyMode},
    config::{TX_GAS_BURN_PERCENT, XELIS_ASSET},
    contract::{
        AssetChanges,
        ContractMetadata,
        ContractModule,
        ContractVersion,
        InterContractPermission,
        Source,
        vm::{self, ContractCaller, ContractStateError, InvokeContract}
    },
    crypto::Hash,
    transaction::{mock::MockChainState, verify::BlockchainContractState},
    versioned::VersionedState
};

mod gas;
mod events;
mod storage;
mod btree;
mod permission;
mod inter_calls;

/// Compiles the given contract code into a Module
#[track_caller]
pub fn compile_contract(environment: &EnvironmentBuilder<ContractMetadata>, enforce_public_params: bool, code: &str) -> anyhow::Result<Module> {
    let tokens = Lexer::new(code)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    let parser = Parser::with(tokens.into_iter(), &environment);
    let (program, _) = parser.parse()
        .expect("contract code");

    let compiler = Compiler::new(&program, environment.environment())
        .with_enforce_public_parameters(enforce_public_params);
    let module = compiler.compile()?;

    Ok(module)
}

/// Creates a contract in the given chain state without invoking its constructor
pub fn create_contract(state: &mut MockChainState, code: &str, version: ContractVersion) -> anyhow::Result<Hash> {
    state.assets.entry(XELIS_ASSET).or_insert_with(|| Some(AssetChanges {
        data: (
            VersionedState::New,
            AssetData::new(
                8,
                "XELIS".to_owned(),
                "XELIS".to_owned(),
                MaxSupplyMode::None,
                AssetOwner::None,
            )
        ),
        circulating_supply: (VersionedState::New, u64::MAX),
    }));

    let module = compile_contract(&state.env_builders[&version], version >= ContractVersion::V1, code)?;

    let hash = Hash::new(rand::random());
    state.internal_set_contract_module(
        hash.clone(),
        ContractModule {
            version,
            module: Arc::new(module),
        },
    );

    Ok(hash)
}

/// Deploys a contract by creating it and invoking its constructor (hook 0)
pub async fn deploy_contract(state: &mut MockChainState, code: &str, version: ContractVersion) -> anyhow::Result<(Hash, vm::ExecutionResult)> {
    let contract_hash = create_contract(state, code, version)?;

    let execution = vm::invoke_contract(
        ContractCaller::System,
        state,
        Cow::Owned(contract_hash.clone()),
        None,
        std::iter::empty(),
        IndexMap::new(),
        100000,
        InvokeContract::Hook(0),
        Cow::Owned(Default::default()),
        true,
    ).await.expect("deploy contract");

    Ok((contract_hash, execution))
}

/// Invokes a contract with the given entry point and parameters
pub async fn invoke_contract(
    state: &mut MockChainState,
    contract: &Hash,
    entry: InvokeContract,
    params: Vec<ValueCell>,
) -> Result<vm::ExecutionResult, ContractStateError<anyhow::Error>> {
    invoke_contract_with_permission(
        state,
        contract,
        entry,
        params,
        InterContractPermission::default(),
    ).await
}

pub async fn invoke_contract_with_permission<'a>(
    state: &mut MockChainState,
    contract: &Hash,
    entry: InvokeContract,
    params: Vec<ValueCell>,
    permission: InterContractPermission,
) -> Result<vm::ExecutionResult, ContractStateError<anyhow::Error>> {
    vm::invoke_contract(
        ContractCaller::System,
        state,
        Cow::Owned(contract.clone()),
        None,
        params.into_iter(),
        IndexMap::new(),
        1_000_000,
        entry,
        Cow::Owned(permission),
        true,
    ).await
}

#[tokio::test]
async fn test_execute_simple_contract() {
    // Compile a simple contract that returns 0 (success)
    let code = r#"
        entry main() {
            return 0
        }
    "#;

    let mut chain_state = MockChainState::new();
    let contract_hash = create_contract(&mut chain_state, code, ContractVersion::V1).expect("create contract");

    // Invoke the contract with entry point 0
    let result = vm::invoke_contract(
        ContractCaller::System,
        &mut chain_state,
        Cow::Owned(contract_hash),
        None,
        std::iter::empty(),
        IndexMap::new(),
        10000,
        InvokeContract::Entry(0),
        Cow::Owned(Default::default()),
        true,
    ).await;

    assert!(result.is_ok(), "contract execution failed: {:?}", result);
    assert!(result.unwrap().is_success(), "contract should return success (exit code 0)");
}

#[tokio::test]
async fn test_contract_with_computation() {
    // Contract that performs some computation
    let code = r#"
        entry main() {
            let a: u64 = 10;
            let b: u64 = 20;
            let sum: u64 = a + b;
            require(sum == 30, "Sum must be 30");
            return 0
        }
    "#;

    let mut chain_state = MockChainState::new();
    let contract_hash = create_contract(&mut chain_state, code, ContractVersion::V1).expect("compile contract");

    // Invoke the contract
    let result = vm::invoke_contract(
        ContractCaller::System,
        &mut chain_state,
        Cow::Owned(contract_hash.clone()),
        None,
        std::iter::empty(),
        IndexMap::new(),
        10000,
        InvokeContract::Entry(0),
        Cow::Owned(Default::default()),
        true,
    ).await;

    assert!(result.is_ok(), "contract execution failed: {:?}", result);
    assert!(result.unwrap().is_success(), "contract should return success");
}

#[tokio::test]
async fn test_contract_with_parameters() {
    // Contract that takes two parameters and uses them
    let code = r#"
        entry add(a: u64, b: u64) {
            let sum: u64 = a + b;
            require(sum == 30, "Sum must be 30");
            return 0
        }
    "#;

    let mut chain_state = MockChainState::new();
    let contract_hash = create_contract(&mut chain_state, code, ContractVersion::V1).expect("compile contract");

    // Invoke the contract with parameters (10 and 20)
    let params = vec![
        Primitive::U64(10).into(),
        Primitive::U64(20).into(),
    ];

    let result = vm::invoke_contract(
        ContractCaller::System,
        &mut chain_state,
        Cow::Owned(contract_hash),
        None,
        params.into_iter(),
        IndexMap::new(),
        10000,
        InvokeContract::Entry(0),
        Cow::Owned(Default::default()),
        true,
    ).await;

    assert!(result.is_ok(), "contract execution failed: {:?}", result);
    assert!(result.unwrap().is_success(), "contract should return success (exit code 0)");
}

#[tokio::test]
async fn test_refund_with_gas_sources() {
    // Contract that performs some computation
    let code = r#"
        entry main() {
            let a: u64 = 10;
            let b: u64 = 20;
            let sum: u64 = a + b;
            require(sum == 30, "Sum must be 30");
            return 0
        }
    "#;

    let mut chain_state = MockChainState::new();
    let contract_hash = create_contract(&mut chain_state, code, ContractVersion::V1).expect("compile contract");

    let contract1 = Hash::new([2u8; 32]);
    let contract2 = Hash::new([3u8; 32]);

    let mut gas_sources = IndexMap::new();
    gas_sources.insert(Source::Contract(contract1.clone()), 5000u64);
    gas_sources.insert(Source::Contract(contract2.clone()), 5000u64);

    // Invoke the contract
    let result = vm::invoke_contract(
        ContractCaller::System,
        &mut chain_state,
        Cow::Owned(contract_hash.clone()),
        None,
        std::iter::empty(),
        gas_sources,
        10000,
        InvokeContract::Entry(0),
        Cow::Owned(Default::default()),
        true,
    ).await;

    let execution = result.expect("contract execution failed");
    assert!(execution.is_success(), "contract should return success");

    // Calculate expected fee gas and burned gas
    let burned_gas = execution.used_gas * TX_GAS_BURN_PERCENT / 100;
    let gas_fee = execution.used_gas - burned_gas;

    assert_eq!(execution.burned_gas, burned_gas, "burned gas should match expected value");
    assert_eq!(execution.fee_gas, gas_fee, "fee gas should match expected value");
    assert_eq!(execution.used_gas, burned_gas + gas_fee, "used gas should equal burned gas plus fee gas");

    let expected_refund = 10000 - execution.used_gas;
    let expected_refund_per_source = expected_refund / 2;

    // Check that the actual contract didn't receive any refund
    let (_, actual_contract_balance) = chain_state.get_contract_balance_for_gas(&contract_hash).await.unwrap();
    assert_eq!(*actual_contract_balance, 0, "actual contract gas balance should be 0 after execution");

    // Check the contract balances
    let (_, contract_balance_1) = chain_state.get_contract_balance_for_gas(&contract1).await.unwrap();
    assert_eq!(*contract_balance_1, expected_refund_per_source, "contract gas balance should be 0 after refund");

    let (_, contract_balance_2) = chain_state.get_contract_balance_for_gas(&contract2).await.unwrap();

    assert_eq!(*contract_balance_2, expected_refund_per_source, "contract gas balance should receive a refund");

    assert_eq!(chain_state.contract_caches.len(), 3);
}