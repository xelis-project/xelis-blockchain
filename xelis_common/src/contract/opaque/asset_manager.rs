use blake3::hash;
use xelis_vm::{
    traits::{JSONHelper, Serializable},
    Context,
    EnvironmentError,
    FnInstance,
    FnParams,
    FnReturnType,
    Value,
    ValueCell
};
use crate::{
    asset::AssetData,
    contract::{from_context, ContractProvider},
    crypto::{Hash, HASH_SIZE}, versioned_type::VersionedState
};

use super::Asset;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct AssetManager;

impl Serializable for AssetManager {}

impl JSONHelper for AssetManager {}

// Constructor for AssetManager
pub fn asset_manager(_: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    Ok(Some(Value::Opaque(AssetManager.into()).into()))
}

// Create a new asset
// Return None if the asset already exists
pub fn asset_manager_create<P: ContractProvider>(_: FnInstance, mut params: FnParams, context: &mut Context) -> FnReturnType {
    let (provider, chain_state) = from_context::<P>(context)?;

    let max_supply = match params.remove(3).into_inner().take_as_optional() {
        Some(v) => Some(v.to_u64()?),
        _ => None,
    };
    let decimals = params.remove(2).into_inner().to_u8()?;
    let name = params.remove(1).into_inner().to_string()?;
    if name.len() > u8::MAX as usize {
        return Err(EnvironmentError::Expect("Asset name is too long".to_string()).into());
    }
    let id = params.remove(0).as_u64()?;

    let mut buffer = [0u8; 40];
    buffer[0..HASH_SIZE].copy_from_slice(chain_state.contract.as_bytes());
    buffer[HASH_SIZE..].copy_from_slice(&id.to_be_bytes());

    let asset_hash = Hash::new(hash(&buffer).into());
    if provider.asset_exists(&asset_hash, chain_state.topoheight)? {
        return Ok(Some(ValueCell::Optional(None)));
    }

    let data = AssetData::new(decimals, name, max_supply);
    provider.register_asset(&asset_hash, chain_state.topoheight, data.clone())?;

    // If we have a max supply, we need to mint it to the contract
    if let Some(max_supply) = max_supply {
        chain_state.changes.balances.insert(asset_hash.clone(), Some((VersionedState::New, max_supply)));
    }

    let asset = Asset {
        hash: asset_hash,
        data,
    };

    Ok(Some(ValueCell::Optional(Some(Value::Opaque(asset.into()).into()))))
}

pub fn asset_manager_get_by_id<P: ContractProvider>(_: FnInstance, params: FnParams, context: &mut Context) -> FnReturnType {
    let id = params[0].as_u64()?;
    let (provider, chain_state) = from_context::<P>(context)?;

    let mut buffer = [0u8; 40];
    buffer[0..HASH_SIZE].copy_from_slice(chain_state.contract.as_bytes());
    buffer[HASH_SIZE..].copy_from_slice(&id.to_be_bytes());

    let asset_hash = Hash::new(hash(&buffer).into());
    let res = match provider.load_asset_data(&asset_hash, chain_state.topoheight)? {
        Some(data) => {
            let asset = Asset {
                hash: asset_hash,
                data,
            };

            Some(Value::Opaque(asset.into()).into())
        }
        None => None
    };

    Ok(Some(ValueCell::Optional(res)))
}