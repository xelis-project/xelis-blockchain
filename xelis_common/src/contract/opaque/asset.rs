use std::hash::Hash as StdHash;
use anyhow::Context as AnyhowContext;
use xelis_vm::{
    traits::{JSONHelper, Serializable},
    Context,
    FnInstance,
    FnParams,
    FnReturnType,
    Value,
    ValueCell
};
use crate::{
    asset::AssetData,
    contract::{from_context, get_balance_from_cache, ContractProvider},
    crypto::Hash,
    versioned_type::VersionedState
};

// Represent an Asset Manager type in the opaque context
#[derive(Clone, Debug)]
pub struct Asset {
    pub hash: Hash,
    pub data: AssetData,
}

impl StdHash for Asset {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.hash.hash(state);
    }
}

impl PartialEq for Asset {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AssetManager;

impl Serializable for Asset {}

impl JSONHelper for Asset {}

// Maximum supply set for this asset
pub fn asset_get_max_supply(zelf: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    let asset: &Asset = zelf?.as_opaque_type()?;
    Ok(Some(ValueCell::Optional(asset.data.get_max_supply().map(|v| Value::U64(v).into()))))
}

// Get the self claimed asset name
pub fn asset_get_name(zelf: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    let asset: &Asset = zelf?.as_opaque_type()?;
    Ok(Some(Value::String(asset.data.get_name().to_owned()).into()))
}

// Get the hash representation of the asset
pub fn asset_get_hash(zelf: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    let asset: &Asset = zelf?.as_opaque_type()?;
    Ok(Some(Value::Opaque(asset.hash.clone().into()).into()))
}

pub fn asset_mint<P: ContractProvider>(zelf: FnInstance, params: FnParams, context: &mut Context) -> FnReturnType {
    let asset: &Asset = zelf?.as_opaque_type()?;
    if asset.data.get_max_supply().is_some() {
        return Ok(Some(Value::Boolean(false).into()))
    }

    let amount = params[0].as_u64()?;
    let (provider, chain_state) = from_context::<P>(context)?;
    let (state, balance) = match get_balance_from_cache(provider, chain_state, asset.hash.clone())? {
        Some((state, balance)) => (state, balance),
        None => (VersionedState::New, 0),
    };

    let new_balance = balance.checked_add(amount)
        .context("Overflow while minting balance")?;

    chain_state.changes.balances.insert(asset.hash.clone(), Some((state, new_balance)));

    Ok(None)
}