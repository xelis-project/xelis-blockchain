use anyhow::Context as AnyhowContext;
use xelis_vm::{
    traits::{JSONHelper, Serializable},
    Context,
    FnInstance,
    FnParams,
    FnReturnType,
    Primitive
};
use crate::{
    contract::{from_context, get_asset_from_cache, get_balance_from_cache, ContractOutput, ContractProvider},
    crypto::Hash,
    versioned_type::VersionedState
};

// Represent an Asset Manager type in the opaque context
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Asset(pub Hash);

impl Serializable for Asset {}

impl JSONHelper for Asset {}

// Maximum supply set for this asset
pub fn asset_get_max_supply<P: ContractProvider>(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let asset: &Asset = zelf?.as_opaque_type()?;

    let (provider, state) = from_context::<P>(context)?;
    let changes = get_asset_from_cache(provider, state, asset.0.clone())?;

    let max_supply = changes.data.as_ref()
        .and_then(|(_, d)| d.get_max_supply().map(|v| Primitive::U64(v).into()))
        .unwrap_or_default();

    Ok(Some(max_supply))
}

// Current supply for this asset
pub fn asset_get_supply<P: ContractProvider>(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let asset: &mut Asset = zelf?.as_opaque_type_mut()?;

    let (provider, state) = from_context::<P>(context)?;
    let topoheight = state.topoheight;
    let changes = get_asset_from_cache(provider, state, asset.0.clone())?;
    let max_supply = changes.data.as_ref()
        .and_then(|(_, d)| d.get_max_supply());

    let supply = match max_supply {
        Some(s) => s,
        None => match changes.supply {
            Some((_, s)) => s,
            None => {
                let (state, supply) = provider.load_asset_supply(&asset.0, topoheight)?
                    .map(|(topo, supply)| (VersionedState::FetchedAt(topo), supply))
                    .unwrap_or((VersionedState::New, 0));

                changes.supply = Some((state, supply));
                supply
            }
        }
    };

    Ok(Some(Primitive::U64(supply).into()))
}

// Get the self claimed asset name
pub fn asset_get_name<P: ContractProvider>(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let asset: &Asset = zelf?.as_opaque_type()?;
    let (provider, state) = from_context::<P>(context)?;
    let changes = get_asset_from_cache(provider, state, asset.0.clone())?;

    let name = changes.data.as_ref()
        .map(|(_, d)| d.get_name().to_owned())
        .context("Failed to get asset name")?;

    Ok(Some(Primitive::String(name).into()))
}

// Get the hash representation of the asset
pub fn asset_get_hash(zelf: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    let asset: &Asset = zelf?.as_opaque_type()?;
    Ok(Some(Primitive::Opaque(asset.0.clone().into()).into()))
}

pub fn asset_mint<P: ContractProvider>(zelf: FnInstance, params: FnParams, context: &mut Context) -> FnReturnType {
    let asset: &mut Asset = zelf?.as_opaque_type_mut()?;
    let (provider, chain_state) = from_context::<P>(context)?;
    let amount = params[0].as_u64()?;

    // Check that we don't have any max supply set
    {
        let topoheight = chain_state.topoheight;
        let changes = get_asset_from_cache::<P>(provider, chain_state, asset.0.clone())?;
        
        let (_, data) = changes.data
        .as_ref()
        .context("failed to retrieve asset data")?;
    
        if data.get_max_supply().is_some() {
            return Ok(Some(Primitive::Boolean(false).into()))
        }

        // Track supply changes
        // Also update the asset supply
        let (mut supply_state, supply) = match changes.supply {
            Some((state, supply)) => (state, supply),
            None => provider.load_asset_supply(&asset.0, topoheight)?
                .map(|(topoheight, supply)| (VersionedState::FetchedAt(topoheight), supply))
                // No supply yet, lets init it to zero
                .unwrap_or((VersionedState::New, 0)),
        };

        // Update the supply
        let new_supply = supply.checked_add(amount)
            .context("Overflow while minting supply")?;
        supply_state.mark_updated();
        changes.supply = Some((supply_state, new_supply));
    }

    // Update the contract balance
    match get_balance_from_cache(provider, chain_state, asset.0.clone())? {
        Some((state, balance)) => {
            let new_balance = balance.checked_add(amount)
            .context("Overflow while minting balance")?;
            state.mark_updated();

            *balance = new_balance;
        },
        v => {
            *v = Some((VersionedState::New, amount))
        },
    };

    // Add to outputs
    chain_state.outputs.push(ContractOutput::Mint {
        asset: asset.0.clone(),
        amount,
    });

    Ok(Some(Primitive::Boolean(true).into()))
}