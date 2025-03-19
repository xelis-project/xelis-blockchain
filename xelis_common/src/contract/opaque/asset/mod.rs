mod manager;

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
    asset::AssetData,
    contract::{
        from_context,
        get_asset_from_cache,
        get_balance_from_cache,
        ChainState,
        ContractOutput,
        ContractProvider
    },
    crypto::Hash,
    versioned_type::VersionedState
};

pub use manager::*;

// Represent an Asset Manager type in the opaque context
#[derive(Clone, Debug)]
pub struct Asset {
    pub hash: Hash,
    pub data: AssetData,
    pub supply: Option<u64>
}

impl std::hash::Hash for Asset {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.hash.hash(state);
    }
}

impl PartialEq for Asset {
    fn eq(&self, other: &Self) -> bool {
        self.hash.eq(&other.hash)
    }
}

impl Eq for Asset {}

impl Serializable for Asset {}

impl JSONHelper for Asset {}

// Maximum supply set for this asset
pub fn asset_get_max_supply<P: ContractProvider>(zelf: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    let asset: &Asset = zelf?.as_opaque_type()?;
    let value = asset.data.get_max_supply()
        .map(|v| Primitive::U64(v).into())
        .unwrap_or_default();

    Ok(Some(value))
}

// Contract hash that created this asset
pub fn asset_get_contract_hash<P: ContractProvider>(zelf: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    let asset: &Asset = zelf?.as_opaque_type()?;
    let hash = asset.data.get_owner()
        .as_ref()
        .map(|v| Primitive::Opaque(v.get_contract().clone().into()))
        .unwrap_or_default();

    Ok(Some(hash.into()))
}

// Contract hash that created this asset
pub fn asset_get_contract_id<P: ContractProvider>(zelf: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    let asset: &Asset = zelf?.as_opaque_type()?;
    let id = asset.data.get_owner()
        .as_ref()
        .map(|v| Primitive::U64(v.get_id()))
        .unwrap_or_default();

    Ok(Some(id.into()))
}

// Current supply for this asset
pub fn asset_get_supply<P: ContractProvider>(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let asset: &mut Asset = zelf?.as_opaque_type_mut()?;

    let (provider, state) = from_context::<P>(context)?;

    // In case the user create several assets instance, to keep the supply in sync
    // We fetch it first from our shared cache
    if let Some(changes) = state.cache.assets.get(&asset.hash) {
        if let Some((_, supply)) = changes.supply {
            return Ok(Some(Primitive::U64(supply).into()))
        }
    }

    // Otherwise fetch it from local type cache
    if let Some(supply) = asset.supply {
        return Ok(Some(Primitive::U64(supply).into()))
    }

    let topoheight = state.topoheight;
    let changes = get_asset_from_cache(provider, state, asset.hash.clone())?;
    let max_supply = changes.data.as_ref()
        .and_then(|(_, d)| d.get_max_supply());

    let supply = match max_supply {
        Some(s) => s,
        None => match changes.supply {
            Some((_, s)) => s,
            None => {
                let (state, supply) = provider.load_asset_supply(&asset.hash, topoheight)?
                    .map(|(topo, supply)| (VersionedState::FetchedAt(topo), supply))
                    .unwrap_or((VersionedState::New, 0));

                changes.supply = Some((state, supply));
                supply
            }
        }
    };

    asset.supply = Some(supply);

    Ok(Some(Primitive::U64(supply).into()))
}

// Get the self claimed asset name
pub fn asset_get_name(zelf: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    let asset: &Asset = zelf?.as_opaque_type()?;
    Ok(Some(Primitive::String(asset.data.get_name().to_owned()).into()))
}

// Get the hash representation of the asset
pub fn asset_get_hash(zelf: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    let asset: &Asset = zelf?.as_opaque_type()?;
    Ok(Some(Primitive::Opaque(asset.hash.clone().into()).into()))
}

// Get the hash representation of the asset
pub fn asset_get_ticker(zelf: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    let asset: &Asset = zelf?.as_opaque_type()?;
    Ok(Some(Primitive::String(asset.data.get_ticker().to_owned()).into()))
}

// are we the owner of this or not
pub fn asset_is_read_only(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let asset: &Asset = zelf?.as_opaque_type()?;
    let state: &ChainState = context.get()
        .context("Chain state not found")?;

    let read_only = asset.data.get_owner()
        .as_ref()
        .map(|v| v.get_contract()) != Some(state.contract);

    Ok(Some(Primitive::Boolean(read_only).into()))
}

pub fn asset_mint<P: ContractProvider>(zelf: FnInstance, params: FnParams, context: &mut Context) -> FnReturnType {
    let asset: &mut Asset = zelf?.as_opaque_type_mut()?;
    let (provider, chain_state) = from_context::<P>(context)?;

    let read_only = asset.data.get_owner()
        .as_ref()
        .map(|v| v.get_contract()) != Some(chain_state.contract);

    if read_only {
        return Ok(Some(Primitive::Boolean(false).into()))
    }

    let amount = params[0].as_u64()?;

    // Check that we don't have any max supply set
    {
        let topoheight = chain_state.topoheight;
        let changes = get_asset_from_cache::<P>(provider, chain_state, asset.hash.clone())?;
        
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
            None => provider.load_asset_supply(&asset.hash, topoheight)?
                .map(|(topoheight, supply)| (VersionedState::FetchedAt(topoheight), supply))
                // No supply yet, lets init it to zero
                .unwrap_or((VersionedState::New, 0)),
        };

        // Update the supply
        let new_supply = supply.checked_add(amount)
            .context("Overflow while minting supply")?;
        supply_state.mark_updated();
        changes.supply = Some((supply_state, new_supply));
        asset.supply = Some(new_supply);
    }

    // Update the contract balance
    match get_balance_from_cache(provider, chain_state, asset.hash.clone())? {
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
        asset: asset.hash.clone(),
        amount,
    });

    Ok(Some(Primitive::Boolean(true).into()))
}