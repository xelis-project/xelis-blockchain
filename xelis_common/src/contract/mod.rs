mod metadata;

use anyhow::Context as AnyhowContext;
use log::info;
use xelis_builder::EnvironmentBuilder;
use xelis_vm::{Context, Environment, FnInstance, FnParams, FnReturnType, Type, Value};

use crate::transaction::Transaction;

pub use metadata::ContractMetadata;


// Build the environment for the contract
pub fn build_environment() -> Environment {
    let mut env = EnvironmentBuilder::default();

    env.get_mut_function("println", None, vec![Type::Any])
        .set_on_call(println_fn);

    // Opaque type but we provide getters
    let tx_type = Type::Struct(env.register_structure("Transaction", vec![]));

    env.register_native_function("nonce", Some(tx_type), vec![], tx_nonce_fn, 5, Some(Type::U64));
    env.build()
}

fn println_fn(_: FnInstance, params: FnParams, _: &mut Context) -> FnReturnType {
    info!("{}", params[0].as_ref());
    Ok(None)
}

fn tx_nonce_fn(_: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let tx: &Transaction = context.get().context("Transaction not found")?;
    Ok(Some(Value::U64(tx.get_nonce()).into()))
}