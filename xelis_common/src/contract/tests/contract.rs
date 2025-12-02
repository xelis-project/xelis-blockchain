use std::{borrow::Cow, sync::Arc};
use indexmap::IndexMap;

use xelis_builder::EnvironmentBuilder;
use xelis_compiler::Compiler;
use xelis_lexer::Lexer;
use xelis_parser::Parser;
use xelis_vm::{Module, Primitive};

use crate::{
    contract::{
        ContractMetadata,
        ContractModule,
        tests::TestChainState,
        vm::{self, ContractCaller, InvokeContract}
    },
    crypto::Hash
};

pub fn compile_contract(environment: &EnvironmentBuilder<ContractMetadata>, code: &str) -> anyhow::Result<Module> {
    let tokens = Lexer::new(code)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    let parser = Parser::with(tokens.into_iter(), &environment);
    let (program, _) = parser.parse()
        .expect("contract code");

    let compiler = Compiler::new(&program, environment.environment());
    let module = compiler.compile()?;

    Ok(module)
}

pub fn create_contract(state: &mut TestChainState, code: &str) -> anyhow::Result<Hash> {
    let module = compile_contract(&state.env, code)?;

    let hash = Hash::zero();
    state.contracts.insert(hash.clone(), ContractModule {
        version: Default::default(),
        module: Arc::new(module.clone()),
    });

    Ok(hash)
}

#[tokio::test]
async fn test_execute_simple_contract() {
    // Compile a simple contract that returns 0 (success)
    let code = r#"
        entry main() {
            return 0
        }
    "#;

    let mut chain_state = TestChainState::new();
    let contract_hash = create_contract(&mut chain_state, code).expect("create contract");

    // Invoke the contract with entry point 0
    let result = vm::invoke_contract(
        ContractCaller::Scheduled(Cow::Owned(Hash::zero()), Cow::Owned(contract_hash.clone())),
        &mut chain_state,
        Cow::Owned(contract_hash),
        None,
        std::iter::empty(),
        IndexMap::new(),
        10000,
        InvokeContract::Entry(0),
        Cow::Owned(Default::default()),
    ).await;

    assert!(result.is_ok(), "contract execution failed: {:?}", result);
    assert!(result.unwrap(), "contract should return success (exit code 0)");
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

    let mut chain_state = TestChainState::new();
    let contract_hash = create_contract(&mut chain_state, code).expect("compile contract");

    // Invoke the contract
    let result = vm::invoke_contract(
        ContractCaller::Scheduled(Cow::Owned(Hash::zero()), Cow::Owned(contract_hash.clone())),
        &mut chain_state,
        Cow::Owned(contract_hash.clone()),
        None,
        std::iter::empty(),
        IndexMap::new(),
        10000,
        InvokeContract::Entry(0),
        Cow::Owned(Default::default()),
    ).await;

    assert!(result.is_ok(), "contract execution failed: {:?}", result);
    assert!(result.unwrap(), "contract should return success");
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

    let mut chain_state = TestChainState::new();
    let contract_hash = create_contract(&mut chain_state, code).expect("compile contract");

    // Invoke the contract with parameters (10 and 20)
    let params = vec![
        Primitive::U64(10).into(),
        Primitive::U64(20).into(),
    ];

    let result = vm::invoke_contract(
        ContractCaller::Scheduled(Cow::Owned(Hash::zero()), Cow::Owned(contract_hash.clone())),
        &mut chain_state,
        Cow::Owned(contract_hash),
        None,
        params.into_iter(),
        IndexMap::new(),
        10000,
        InvokeContract::Entry(0),
        Cow::Owned(Default::default()),
    ).await;

    assert!(result.is_ok(), "contract execution failed: {:?}", result);
    assert!(result.unwrap(), "contract should return success (exit code 0)");
}