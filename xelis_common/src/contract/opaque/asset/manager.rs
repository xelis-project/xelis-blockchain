use blake3::hash;
use xelis_vm::{
    Context,
    EnvironmentError,
    FnInstance,
    FnParams,
    FnReturnType,
    Primitive,
    SysCallResult
};
use crate::{
    asset::{AssetData, AssetOwner},
    config::{COST_PER_TOKEN, XELIS_ASSET},
    contract::{
        from_context,
        get_balance_from_cache,
        get_cache_for_contract,
        get_mut_balance_for_contract,
        get_optional_asset_from_cache,
        record_burned_asset,
        AssetChanges,
        ContractLog,
        ContractProvider,
        ModuleMetadata
    },
    crypto::{Hash, HASH_SIZE},
    versioned_type::VersionedState
};
use super::Asset;

// Maximum size for the ticker
pub const TICKER_LEN: usize = 8;

// Verify if the asset str is valid
fn is_valid_str_for_asset(name: &str, whitespace: bool, uppercase_only: bool) -> bool {
    if whitespace {
        if name.starts_with(" ") || name.ends_with(" ") {
            return false
        }
    }

    name.chars().all(|c| is_valid_char_for_asset(c, whitespace, uppercase_only))
}

// Check if the char for an asset is valid
fn is_valid_char_for_asset(c: char, whitespace: bool, uppercase_only: bool) -> bool {
    match c {
        'A'..='Z'
        | '0'..='9' => true,
        | 'a'..='z' if !uppercase_only => true,
        | ' ' if whitespace => true,
        _ => false
    }
}

// Create a new asset
// Return None if the asset already exists
pub async fn asset_create<'a, 'ty, 'r, P: ContractProvider>(_: FnInstance<'a>, mut params: FnParams, metadata: &ModuleMetadata, context: &mut Context<'ty, 'r>) -> FnReturnType<ModuleMetadata> {
    let (provider, state) = from_context::<P>(context)?;

    let max_supply = match params.remove(4).into_owned().take_as_optional()? {
        Some(v) => Some(v.to_u64()?),
        _ => None,
    };
    let decimals = params.remove(3)
        .into_owned()
        .to_u8()?;

    let ticker = params.remove(2)
        .into_owned()
        .into_string()?;

    if ticker.len() > TICKER_LEN {
        return Err(EnvironmentError::Expect("Asset ticker is too long".to_owned()).into());
    }

    // Ticker can be ASCII & upper case only
    // No whitespace is allowed in it
    if !is_valid_str_for_asset(&ticker, false, true) {
        return Err(EnvironmentError::Expect("Asset ticker must be ASCII only".to_owned()).into());
    }

    let name = params.remove(1)
        .into_owned()
        .into_string()?;
    if name.len() > u8::MAX as usize {
        return Err(EnvironmentError::Expect("Asset name is too long".to_owned()).into());
    }

    // Name can be ASCII only
    if !is_valid_str_for_asset(&name, true, false) {
        return Err(EnvironmentError::Expect("Asset name must be ASCII only".to_owned()).into());
    }

    // Check that we have enough XEL in the balance
    let balance = get_balance_from_cache(provider, state, metadata.contract.clone(), XELIS_ASSET).await?;
    if balance.is_none_or(|(_, balance)| balance < COST_PER_TOKEN) {
        return Err(EnvironmentError::Expect("Insufficient XEL funds in contract balance for token creation".to_owned()).into());
    }

    // Now proceed to generate the asset hash
    let id = params.remove(0).as_u64()?;

    let mut buffer = [0u8; 40];
    buffer[0..HASH_SIZE].copy_from_slice(metadata.contract.as_bytes());
    buffer[HASH_SIZE..].copy_from_slice(&id.to_be_bytes());

    let asset_hash = Hash::new(hash(&buffer).into());

    // We must be sure that we don't have this asset already
    let asset_cache = get_optional_asset_from_cache(provider, state, asset_hash.clone()).await?;
    if asset_cache.is_some() {
        return Ok(SysCallResult::Return(Primitive::Null.into()));
    }

    let data = AssetData::new(decimals, name, ticker, max_supply, Some(AssetOwner::new(metadata.contract.clone(), id)));
    *asset_cache = Some(AssetChanges {
        data: (VersionedState::New, data.clone()),
        circulating_supply: (VersionedState::New, max_supply.unwrap_or(0)),
    });

    // Pay the fee by reducing the contract balance
    // and record the burn in the circulating supply
    {
        let (versioned_state, balance) = get_mut_balance_for_contract(provider, state, metadata.contract.clone(), XELIS_ASSET).await?;
        *balance -= COST_PER_TOKEN;
        versioned_state.mark_updated();
    
        record_burned_asset(provider, state, metadata.contract.clone(), XELIS_ASSET, COST_PER_TOKEN).await?;
    }

    // If we have a max supply, we need to mint it to the contract
    if let Some(max_supply) = max_supply {
        // We don't bother to check if it already exists, because it shouldn't exist before we create it.
        get_cache_for_contract(&mut state.caches, state.global_caches, metadata.contract.clone())
            .balances
            .insert(asset_hash.clone(), Some((VersionedState::New, max_supply)));
    }

    state.outputs.push(ContractLog::NewAsset { contract: metadata.contract.clone(), asset: asset_hash.clone() });

    let asset = Asset {
        hash: asset_hash
    };
    Ok(SysCallResult::Return(Primitive::Opaque(asset.into()).into()))
}

pub async fn asset_get_by_id<'a, 'ty, 'r, P: ContractProvider>(_: FnInstance<'a>, params: FnParams, metadata: &ModuleMetadata, context: &mut Context<'ty, 'r>) -> FnReturnType<ModuleMetadata> {
    let id = params[0].as_u64()?;
    let (provider, chain_state) = from_context::<P>(context)?;

    let mut buffer = [0u8; 40];
    buffer[0..HASH_SIZE].copy_from_slice(metadata.contract.as_bytes());
    buffer[HASH_SIZE..].copy_from_slice(&id.to_be_bytes());

    let asset_hash = Hash::new(hash(&buffer).into());
    if get_optional_asset_from_cache(provider, chain_state, asset_hash.clone()).await?.is_none() {
        return Ok(SysCallResult::Return(Primitive::Null.into()))
    }

    let asset = Asset {
        hash: asset_hash
    };
    Ok(SysCallResult::Return(Primitive::Opaque(asset.into()).into()))
}

pub async fn asset_get_by_hash<'a, 'ty, 'r, P: ContractProvider>(_: FnInstance<'a>, mut params: FnParams, _: &ModuleMetadata, context: &mut Context<'ty, 'r>) -> FnReturnType<ModuleMetadata> {
    let hash: Hash = params.remove(0)
        .into_owned()
        .into_opaque_type()?;

    let (provider, chain_state) = from_context::<P>(context)?;

    if get_optional_asset_from_cache(provider, chain_state, hash.clone()).await?.is_none() {
        return Ok(SysCallResult::Return(Primitive::Null.into()))
    }

    let asset = Asset {
        hash
    };
    Ok(SysCallResult::Return(Primitive::Opaque(asset.into()).into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_various_asset_names() {
        assert!(is_valid_str_for_asset("XELIS", true, false));
        assert!(is_valid_str_for_asset("XELISAI99", true, false));
        assert!(is_valid_str_for_asset("XELIS POW 123", true, false));
        assert!(is_valid_str_for_asset("ZZZZZZ", true, true));

        // check only uppercase
        assert!(!is_valid_str_for_asset("ZZZZZZzzzZ", true, true));

        // check whitespaces
        assert!(!is_valid_str_for_asset(" XELIS", true, false));
        assert!(!is_valid_str_for_asset("XELIS   ", true, false));
    }
}