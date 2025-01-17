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
    contract::{from_context, get_balance_from_cache, ContractOutput, ContractProvider},
    crypto::Hash,
    versioned_type::VersionedState
};

// Represent an Asset Manager type in the opaque context
#[derive(Clone, Debug)]
pub struct Asset {
    pub hash: Hash,
    // Stored data
    pub data: AssetData,
    pub supply: Option<(VersionedState, u64)>,
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

impl Serializable for Asset {}

impl JSONHelper for Asset {}

// Maximum supply set for this asset
pub fn asset_get_max_supply(zelf: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    let asset: &Asset = zelf?.as_opaque_type()?;
    Ok(Some(ValueCell::Optional(asset.data.get_max_supply().map(|v| Value::U64(v).into()))))
}

// Current supply for this asset
pub fn asset_get_supply<P: ContractProvider>(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let asset: &mut Asset = zelf?.as_opaque_type_mut()?;
    let supply = match asset.data.get_max_supply() {
        Some(v) => v,
        None => match asset.supply {
            Some((_, v)) => v,
            None => {
                // TODO: We need to fetch from cache, or from provider
                let (provider, chain_state) = from_context::<P>(context)?;
                let res = match provider.load_asset_supply(&asset.hash, chain_state.topoheight)? {
                    Some((topo, v)) => (VersionedState::FetchedAt(topo), v),
                    None => (VersionedState::New, 0)
                };

                asset.supply = Some(res);
                res.1
            }
        }
    };
    Ok(Some(Value::U64(supply).into()))
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
    let asset: &mut Asset = zelf?.as_opaque_type_mut()?;
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

    // Also update the asset supply
    match asset.supply.as_mut() {
        Some((state, supply)) => {
            *supply = supply.checked_add(amount)
                .context("Overflow while minting supply")?;

            state.mark_updated();
        },
        None => {
            let res = match provider.load_asset_supply(&asset.hash, chain_state.topoheight)? {
                Some((topo, mut supply)) => {
                    supply = supply.checked_add(amount)
                        .context("Overflow while minting supply")?;

                    (VersionedState::Updated(topo), supply)
                },
                None => (VersionedState::New, amount)
            };

            asset.supply = Some(res);
        }
    };

    chain_state.changes.balances.insert(asset.hash.clone(), Some((state, new_balance)));

    // Add to outputs
    chain_state.outputs.push(ContractOutput::Mint {
        asset: asset.hash.clone(),
        amount,
    });

    Ok(None)
}