use anyhow::Context as AnyhowContext;
use blake3::hash;
use xelis_vm::{
    traits::{JSONHelper, Serializable},
    Context,
    FnInstance,
    FnParams,
    FnReturnType,
    Value
};
use crate::{config::COST_PER_TOKEN, contract::ChainState, crypto::{Hash, HASH_SIZE}};

// Represent an Asset Manager type in the opaque context
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct OpaqueAsset(pub Hash);

impl Serializable for OpaqueAsset {}

impl JSONHelper for OpaqueAsset {}

// Create an instance of the Asset Manager opaque type
// This will create the asset on chain if its not already created
pub fn get_asset_by_id(_: FnInstance, mut params: FnParams, context: &mut Context) -> FnReturnType {
    let chain_state: &ChainState = context.get().context("chain state not found")?;
    let id = params.remove(0).as_u64()?;
    let contract = chain_state.contract;

    // Generate a hash that combine the contract hash, and the asset id
    let mut buffer = [0u8; 40];
    buffer[..HASH_SIZE].copy_from_slice(contract.as_bytes());
    buffer[HASH_SIZE..].copy_from_slice(&id.to_be_bytes());
    let token_asset = Hash::new(hash(&buffer).into());

    // If the asset was not yet registered, pay the cost to register it
    context.increase_gas_usage(COST_PER_TOKEN)?;

    Ok(Some(Value::Opaque(OpaqueAsset(contract.clone()).into()).into()))
}

// get hash from asset manager
pub fn asset_manager_hash(zelf: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    let asset_manager: &OpaqueAsset = zelf?.as_opaque_type()?;
    Ok(Some(Value::Opaque(asset_manager.0.clone().into()).into()))
}