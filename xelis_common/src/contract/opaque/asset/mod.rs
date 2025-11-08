mod manager;

use anyhow::Context as AnyhowContext;
use xelis_vm::{
    traits::{JSONHelper, Serializable},
    Context,
    EnvironmentError,
    FnInstance,
    FnParams,
    FnReturnType,
    Primitive,
    SysCallResult,
    ValueCell
};
use crate::{
    contract::{
        from_context,
        get_asset_changes_for_hash,
        get_asset_changes_for_hash_mut,
        get_balance_from_cache,
        ChainState,
        ContractLog,
        ContractProvider,
        ContractMetadata,
        ModuleMetadata,
    },
    crypto::Hash,
    versioned_type::VersionedState
};

pub use manager::*;

// Represent an Asset Manager type in the opaque context
// It only holds the asset hash because the AssetData
// may be updated at any time in the chain state
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
pub fn asset_get_max_supply<P: ContractProvider>(zelf: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, context: &mut Context) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    let asset: &Asset = zelf.as_opaque_type()?;
    let state: &ChainState = context.get()
        .context("Chain state not found")?;
    let changes = get_asset_changes_for_hash(state, &asset.hash)?;
    let value: ValueCell = changes.data.1
        .get_max_supply()
        .get_max()
        .map(|v| Primitive::U64(v).into())
        .unwrap_or_default();

    Ok(SysCallResult::Return(value.into()))
}

// Contract hash that created this asset
pub fn asset_get_contract_hash<P: ContractProvider>(zelf: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, context: &mut Context) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    let asset: &Asset = zelf.as_opaque_type()?;
    let state: &ChainState = context.get()
        .context("Chain state not found")?;
    let changes = get_asset_changes_for_hash(state, &asset.hash)?;
    let hash = changes.data.1.get_owner()
        .get_contract()
        .map(|v| Primitive::Opaque(v.clone().into()))
        .unwrap_or_default();

    Ok(SysCallResult::Return(hash.into()))
}

// Contract hash that created this asset
pub fn asset_get_contract_id<P: ContractProvider>(zelf: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, context: &mut Context) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    let asset: &Asset = zelf.as_opaque_type()?;
    let state: &ChainState = context.get()
        .context("Chain state not found")?;
    let changes = get_asset_changes_for_hash(state, &asset.hash)?;
    let id = changes.data.1.get_owner()
        .get_id()
        .map(|v| Primitive::U64(v))
        .unwrap_or_default();

    Ok(SysCallResult::Return(id.into()))
}

// Circulating supply for this asset
pub async fn asset_get_supply<'a, 'ty, 'r, P: ContractProvider>(zelf: FnInstance<'a>, _: FnParams, _: &ModuleMetadata<'_>, context: &mut Context<'ty, 'r>) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    let asset: &Asset = zelf.as_opaque_type()?;
    let (_, state) = from_context::<P>(context)?;
    let changes = get_asset_changes_for_hash_mut(state, &asset.hash)?;
    Ok(SysCallResult::Return(Primitive::U64(changes.circulating_supply.1).into()))
}

// Get the self claimed asset name
pub fn asset_get_name(zelf: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, context: &mut Context) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    let asset: &Asset = zelf.as_opaque_type()?;
    let state: &ChainState = context.get()
        .context("Chain state not found")?;
    let changes = get_asset_changes_for_hash(state, &asset.hash)?;
    Ok(SysCallResult::Return(Primitive::String(changes.data.1.get_name().to_owned()).into()))
}

// Get the hash representation of the asset
pub fn asset_get_hash(zelf: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, _: &mut Context) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    let asset: &Asset = zelf.as_opaque_type()?;
    Ok(SysCallResult::Return(Primitive::Opaque(asset.hash.clone().into()).into()))
}

// Get the contract hash owner of this asset
pub fn asset_get_owner(zelf: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, context: &mut Context) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    let asset: &Asset = zelf.as_opaque_type()?;
    let state: &ChainState = context.get()
        .context("Chain state not found")?;

    let changes = get_asset_changes_for_hash(state, &asset.hash)?;
    let owner_hash = match changes.data.1.get_owner().get_contract() {
        Some(v) => Primitive::Opaque(v.clone().into()),
        None => Primitive::Null
    };
    Ok(SysCallResult::Return(owner_hash.into()))
}

// Get the contract creator
pub fn asset_get_creator(zelf: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, context: &mut Context) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    let asset: &Asset = zelf.as_opaque_type()?;
    let state: &ChainState = context.get()
        .context("Chain state not found")?;

    let changes = get_asset_changes_for_hash(state, &asset.hash)?;
    let creator_hash = match changes.data.1.get_owner().get_origin_contract() {
        Some(v) => Primitive::Opaque(v.clone().into()),
        None => Primitive::Null
    };
    Ok(SysCallResult::Return(creator_hash.into()))
}

// Get the contract id owner of this asset
pub fn asset_get_creator_id(zelf: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, context: &mut Context) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    let asset: &Asset = zelf.as_opaque_type()?;
    let state: &ChainState = context.get()
        .context("Chain state not found")?;

    let changes = get_asset_changes_for_hash(state, &asset.hash)?;
    let owner_id = match changes.data.1.get_owner().get_id() {
        Some(v) => Primitive::U64(v),
        None => Primitive::Null
    };
    Ok(SysCallResult::Return(owner_id.into()))
}

// Get the hash representation of the asset
pub fn asset_get_ticker(zelf: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, context: &mut Context) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    let asset: &Asset = zelf.as_opaque_type()?;
    let state: &ChainState = context.get()
        .context("Chain state not found")?;
    let changes = get_asset_changes_for_hash(state, &asset.hash)?;
    Ok(SysCallResult::Return(Primitive::String(changes.data.1.get_ticker().to_owned()).into()))
}

// are we the owner of this or not
pub fn asset_is_read_only(zelf: FnInstance, _: FnParams, metadata: &ModuleMetadata<'_>, context: &mut Context) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    let asset: &Asset = zelf.as_opaque_type()?;
    let state: &ChainState = context.get()
        .context("Chain state not found")?;

    let changes = get_asset_changes_for_hash(state, &asset.hash)?;
    let is_owner = changes.data.1
        .get_owner()
        .is_owner(&metadata.metadata.contract);

    Ok(SysCallResult::Return(Primitive::Boolean(!is_owner).into()))
}

pub fn asset_is_mintable(zelf: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, context: &mut Context) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    let asset: &Asset = zelf.as_opaque_type()?;
    let state: &ChainState = context.get()
        .context("Chain state not found")?;
    let changes = get_asset_changes_for_hash(state, &asset.hash)?;
    Ok(SysCallResult::Return(Primitive::Boolean(changes.data.1.get_max_supply().is_mintable()).into()))
}

pub async fn asset_transfer_ownership<'a, 'ty, 'r, P: ContractProvider>(zelf: FnInstance<'a>, mut params: FnParams, metadata: &ModuleMetadata<'_>, context: &mut Context<'ty, 'r>) -> FnReturnType<ContractMetadata> {
    let param: Hash = params.remove(0)
        .into_owned()
        .into_opaque_type()?;

    let zelf = zelf?;
    let asset: &Asset = zelf.as_opaque_type()?;
    let (provider, state) = from_context::<P>(context)?;

    // Ensure that the contract hash is a valid one
    if !provider.has_contract(&asset.hash, state.topoheight).await? {
        return Ok(SysCallResult::Return(Primitive::Boolean(false).into()))
    }

    if param == metadata.metadata.contract {
        // Cannot transfer to self
        return Ok(SysCallResult::Return(Primitive::Boolean(false).into()))
    }

    let changes = get_asset_changes_for_hash_mut(state, &asset.hash)?;
    let owner = changes.data.1.get_owner_mut();
    Ok(SysCallResult::Return(Primitive::Boolean(owner.transfer(&metadata.metadata.contract, param)).into()))
}

pub async fn asset_mint<'a, 'ty, 'r, P: ContractProvider>(zelf: FnInstance<'a>, params: FnParams, metadata: &ModuleMetadata<'_>, context: &mut Context<'ty, 'r>) -> FnReturnType<ContractMetadata> {
    let mut zelf = zelf?;
    let asset: &mut Asset = zelf.as_opaque_type_mut()?;
    let (provider, state) = from_context::<P>(context)?;

    let changes = get_asset_changes_for_hash_mut(state, &asset.hash)?;
    let asset_data = &mut changes.data.1;
    let read_only = !asset_data
        .get_owner()
        .is_owner(&metadata.metadata.contract);

    if read_only {
        return Ok(SysCallResult::Return(Primitive::Boolean(false).into()))
    }

    let amount = params[0].as_u64()?;

    // Check if we can mint that amount
    {
        if !asset_data.get_max_supply().allow_minting(changes.circulating_supply.1, amount) {
            return Ok(SysCallResult::Return(Primitive::Boolean(false).into()))
        }

        // Track supply changes
        // Also update the asset supply

        // Update the supply
        let new_supply = changes.circulating_supply.1.checked_add(amount)
            .context("Overflow while minting supply")?;

        changes.circulating_supply.0.mark_updated();
        changes.circulating_supply.1 = new_supply;
    }

    // Update the contract balance
    match get_balance_from_cache(provider, state, metadata.metadata.contract.clone(), asset.hash.clone()).await? {
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
    state.outputs.push(ContractLog::Mint {
        contract: metadata.metadata.contract.clone(),
        asset: asset.hash.clone(),
        amount,
    });

    Ok(SysCallResult::Return(Primitive::Boolean(true).into()))
}

pub fn max_supply_mode_get_max_supply(zelf: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, _: &mut Context) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    let (id, fields) = zelf.as_enum()?;

    let max_supply = match id {
        0 => None,
        1 | 2 if fields.len() == 1 => Some(fields[0].as_ref().as_u64()?),
        _ => return Err(EnvironmentError::InvalidType)
    };

    Ok(SysCallResult::Return(match max_supply {
        Some(v) => Primitive::U64(v).into(),
        None => Primitive::Null.into()
    }))
}

pub fn max_supply_mode_is_mintable(zelf: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, _: &mut Context) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    let (id, _) = zelf.as_enum()?;

    let mintable = match id {
        0 => true, // None
        1 => false, // Fixed
        2 => true, // Mintable
        _ => return Err(EnvironmentError::InvalidType)
    };
    Ok(SysCallResult::Return(Primitive::Boolean(mintable).into()))
}