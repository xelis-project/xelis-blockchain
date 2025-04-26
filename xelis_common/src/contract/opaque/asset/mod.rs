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
    contract::{
        from_context,
        get_balance_from_cache,
        get_asset_changes_for_hash,
        get_asset_changes_for_hash_mut,
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
    pub hash: Hash
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
pub fn asset_get_max_supply<P: ContractProvider>(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let asset: &Asset = zelf?.as_opaque_type()?;
    let state: &ChainState = context.get()
        .context("Chain state not found")?;
    let changes = get_asset_changes_for_hash(state, &asset.hash)?;
    let value = changes.data.1.get_max_supply()
        .map(|v| Primitive::U64(v).into())
        .unwrap_or_default();

    Ok(Some(value))
}

// Contract hash that created this asset
pub fn asset_get_contract_hash<P: ContractProvider>(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let asset: &Asset = zelf?.as_opaque_type()?;
    let state: &ChainState = context.get()
        .context("Chain state not found")?;
    let changes = get_asset_changes_for_hash(state, &asset.hash)?;
    let hash = changes.data.1.get_owner()
        .as_ref()
        .map(|v| Primitive::Opaque(v.get_contract().clone().into()))
        .unwrap_or_default();

    Ok(Some(hash.into()))
}

// Contract hash that created this asset
pub fn asset_get_contract_id<P: ContractProvider>(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let asset: &Asset = zelf?.as_opaque_type()?;
    let state: &ChainState = context.get()
        .context("Chain state not found")?;
    let changes = get_asset_changes_for_hash(state, &asset.hash)?;
    let id = changes.data.1.get_owner()
        .as_ref()
        .map(|v| Primitive::U64(v.get_id()))
        .unwrap_or_default();

    Ok(Some(id.into()))
}

// Emitted supply for this asset
pub fn asset_get_supply<P: ContractProvider>(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let asset: &Asset = zelf?.as_opaque_type()?;
    let (provider, state) = from_context::<P>(context)?;

    let topoheight = state.topoheight;
    let changes = get_asset_changes_for_hash_mut(state, &asset.hash)?;
    if let Some((_, supply)) = changes.supply {
        return Ok(Some(Primitive::U64(supply).into()))
    }

    let supply = provider.load_asset_supply(&asset.hash, topoheight)?
        .map(|(topo, v)| (VersionedState::FetchedAt(topo), v))
        .unwrap_or((VersionedState::New, 0));

    changes.supply = Some(supply);
    Ok(Some(Primitive::U64(supply.1).into()))
}

// Get the self claimed asset name
pub fn asset_get_name(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let asset: &Asset = zelf?.as_opaque_type()?;
    let state: &ChainState = context.get()
        .context("Chain state not found")?;
    let changes = get_asset_changes_for_hash(state, &asset.hash)?;
    Ok(Some(Primitive::String(changes.data.1.get_name().to_owned()).into()))
}

// Get the hash representation of the asset
pub fn asset_get_hash(zelf: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    let asset: &Asset = zelf?.as_opaque_type()?;
    Ok(Some(Primitive::Opaque(asset.hash.clone().into()).into()))
}

// Get the hash representation of the asset
pub fn asset_get_ticker(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let asset: &Asset = zelf?.as_opaque_type()?;
    let state: &ChainState = context.get()
        .context("Chain state not found")?;
    let changes = get_asset_changes_for_hash(state, &asset.hash)?;
    Ok(Some(Primitive::String(changes.data.1.get_ticker().to_owned()).into()))
}

// are we the owner of this or not
pub fn asset_is_read_only(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let asset: &Asset = zelf?.as_opaque_type()?;
    let state: &ChainState = context.get()
        .context("Chain state not found")?;

    let changes = get_asset_changes_for_hash(state, &asset.hash)?;
    let read_only = changes.data.1
        .get_owner()
        .as_ref()
        .map(|v| v.get_contract()) != Some(state.contract);

    Ok(Some(Primitive::Boolean(read_only).into()))
}

pub fn asset_transfer_ownership<P: ContractProvider>(zelf: FnInstance, mut params: FnParams, context: &mut Context) -> FnReturnType {
    let param: Hash = params.remove(0)
        .into_owned()?
        .into_opaque_type()?;

    let asset: &Asset = zelf?.as_opaque_type()?;
    let (provider, state) = from_context::<P>(context)?;

    // Ensure that the contract hash is a valid one
    if !provider.has_contract(&asset.hash, state.topoheight)? {
        return Ok(Some(Primitive::Boolean(false).into()))
    }

    let contract = state.contract.clone();
    let changes = get_asset_changes_for_hash_mut(state, &asset.hash)?;
    Ok(Some(match changes.data.1.get_owner_mut() {
        Some(data) if *data.get_contract() == contract => {
            data.set_contract(param);
            changes.data.0.mark_updated();
            Primitive::Boolean(true)
        },
        _ => Primitive::Boolean(false)
    }.into()))
}

pub fn asset_mint<P: ContractProvider>(zelf: FnInstance, params: FnParams, context: &mut Context) -> FnReturnType {
    let asset: &mut Asset = zelf?.as_opaque_type_mut()?;
    let (provider, chain_state) = from_context::<P>(context)?;

    let topoheight = chain_state.topoheight;
    let contract = chain_state.contract.clone();
    let changes = get_asset_changes_for_hash_mut(chain_state, &asset.hash)?;
    let asset_data = &mut changes.data.1;
    let read_only = asset_data
        .get_owner()
        .as_ref()
        .map(|v| v.get_contract()) != Some(&contract);

    if read_only {
        return Ok(Some(Primitive::Boolean(false).into()))
    }

    let amount = params[0].as_u64()?;

    // Check that we don't have any max supply set
    {
        if asset_data.get_max_supply().is_some() {
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