use log::info;
use xelis_builder::EnvironmentBuilder;
use xelis_vm::{Context, Environment, FnInstance, FnParams, FnReturnType, Type};

pub fn build_environment() -> Environment {
    let mut env = EnvironmentBuilder::default();

    env.get_mut_function("println", None, vec![Type::Any])
        .set_on_call(println_fn);

    env.build()
}

fn println_fn(_: FnInstance, params: FnParams, _: &mut Context) -> FnReturnType {
    info!("{}", params[0].as_ref());
    Ok(None)
}