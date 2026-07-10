use std::hash::Hasher;

use anyhow::Context as AnyhowContext;
use curve25519_dalek::Scalar;
use xelis_vm::{
    impl_opaque,
    traits::{DynHash, Serializable},
    VMContext,
    FnInstance,
    FnParams,
    FnReturnType,
    Primitive,
    SysCallResult
};
use crate::{
    account::CiphertextCache,
    contract::{
        CIPHERTEXT_OPAQUE_ID,
        ContractMetadata,
        DeterministicRandom,
        ModuleMetadata,
        OpaqueRistrettoPoint,
        OpaqueScalar,
        get_cache_for_contract,
        state_from_context,
    },
    crypto::{
        Address,
        elgamal::*
    },
    serializer::{Serializer, Writer}
};

impl Serializable for CiphertextCache {
    fn serialize(&self, buffer: &mut Vec<u8>) -> usize {
        let mut writer = Writer::new(buffer);
        writer.write_u8(CIPHERTEXT_OPAQUE_ID);
        self.write(&mut writer);
        writer.total_write()
    }

    fn is_serializable(&self) -> bool {
        true
    }

    fn get_size(&self) -> usize {
        RISTRETTO_COMPRESSED_SIZE + RISTRETTO_COMPRESSED_SIZE
    }
}

impl DynHash for CiphertextCache {
    fn dyn_hash(&self, state: &mut dyn Hasher) {
        state.write(&self.to_bytes());
    }

    fn is_hashable(&self) -> bool {
        true
    }
}

impl_opaque!(
    "Ciphertext",
    CiphertextCache,
    display,
    json
);

pub fn ciphertext_mul_plaintext(zelf: FnInstance, mut params: FnParams, _: &ModuleMetadata<'_>, _: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let mut zelf = zelf?;
    let zelf: &mut CiphertextCache = zelf.as_opaque_type_mut()?;
    let value = params.remove(0)
        .as_u64()?;

    let computable = zelf.computable()
        .context("Ciphertext not computable")?;

    *computable = &*computable * Scalar::from(value);

    Ok(SysCallResult::None)
}

pub fn ciphertext_div_plaintext(zelf: FnInstance, mut params: FnParams, _: &ModuleMetadata<'_>, _: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let mut zelf = zelf?;
    let zelf: &mut CiphertextCache = zelf.as_opaque_type_mut()?;
    let value = params.remove(0)
        .as_u64()?;

    if value == 0 {
        return Err(anyhow::anyhow!("Division by zero").into());
    }

    let computable = zelf.computable()
        .context("Ciphertext not computable")?;

    *computable = &*computable * Scalar::from(value).invert();

    Ok(SysCallResult::None)
}

pub fn ciphertext_add_plaintext(zelf: FnInstance, mut params: FnParams, _: &ModuleMetadata<'_>, _: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let mut zelf = zelf?;
    let zelf: &mut CiphertextCache = zelf.as_opaque_type_mut()?;
    let value = params.remove(0)
        .as_u64()?;

    let mut computable = zelf.computable()
        .context("Ciphertext not computable")?;

    computable += Scalar::from(value);

    Ok(SysCallResult::None)
}

pub fn ciphertext_sub_plaintext(zelf: FnInstance, mut params: FnParams, _: &ModuleMetadata<'_>, _: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let mut zelf = zelf?;
    let zelf: &mut CiphertextCache = zelf.as_opaque_type_mut()?;
    let value = params.remove(0)
        .as_u64()?;

    let mut computable = zelf.computable()
        .context("Ciphertext not computable")?;

    computable -= Scalar::from(value);

    Ok(SysCallResult::None)
}

pub fn ciphertext_generate(_: FnInstance, mut params: FnParams, metadata: &ModuleMetadata<'_>, context: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let amount = params.remove(1)
        .into_owned()
        .as_u64()?;
    let address: Address = params.remove(0)
        .into_owned()
        .into_opaque_type()?;

    let key = address.get_public_key()
        .decompress()
        .context("Invalid public key")?;

    let state = state_from_context(context)?;
    let cache = get_cache_for_contract(&mut state.changes.caches, state.global_caches, metadata.metadata.contract_executor.clone(), state.cache_clone_refs);
    if cache.random.is_none() {
        cache.random = Some(DeterministicRandom::new(&metadata.metadata.contract_executor, state.block_hash, state.topoheight, &state.caller.get_hash()));
    }

    let random = cache.random.as_mut()
        .context("Random not initialized")?;

    let mut buffer = [0u8; 64];
    random.fill(&mut buffer)
        .context("filling random buffer")?;

    let scalar = Scalar::from_bytes_mod_order_wide(&buffer);
    let opening = PedersenOpening::from_scalar(scalar);

    let ciphertext = CiphertextCache::Decompressed(None, key.encrypt_with_opening(amount, &opening));
    Ok(SysCallResult::Return(Primitive::Opaque(ciphertext.into()).into()))
}

pub fn ciphertext_from(_: FnInstance, mut params: FnParams, _: &ModuleMetadata<'_>, _: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let handle: OpaqueRistrettoPoint = params.remove(1)
        .into_owned()
        .into_opaque_type()?;
    let commitment: OpaqueRistrettoPoint = params.remove(0)
        .into_owned()
        .into_opaque_type()?;

    let ciphertext = match (handle, commitment) {
        (OpaqueRistrettoPoint::Compressed(handle), OpaqueRistrettoPoint::Compressed(commitment)) => {
            CiphertextCache::Compressed(CompressedCiphertext::new(CompressedCommitment::new(commitment), CompressedHandle::new(handle)))
        },
        (OpaqueRistrettoPoint::Decompressed(compressed_handle, handle), OpaqueRistrettoPoint::Decompressed(compressed_commitment, commitment)) => {
            let compressed = match (compressed_handle, compressed_commitment) {
                (Some(compressed_handle), Some(compressed_commitment)) => Some(CompressedCiphertext::new(CompressedCommitment::new(compressed_commitment), CompressedHandle::new(compressed_handle))),
                _ => None,
            };

            CiphertextCache::Decompressed(compressed, Ciphertext::new(PedersenCommitment::from_point(commitment), DecryptHandle::from_point(handle)))
        },
        (handle, commitment) => {
            let handle = handle.into_point()
                .context("Invalid handle")?;
            let commitment = commitment.into_point()
                .context("Invalid commitment")?;

            CiphertextCache::Decompressed(None, Ciphertext::new(PedersenCommitment::from_point(commitment), DecryptHandle::from_point(handle)))
        }
    };

    Ok(SysCallResult::Return(Primitive::Opaque(ciphertext.into()).into()))
}

pub fn ciphertext_add_ct(zelf: FnInstance, mut params: FnParams, _: &ModuleMetadata<'_>, _: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let mut zelf = zelf?;

    let other: CiphertextCache = params.remove(0)
        .into_owned()
        .into_opaque_type()?;

    let ct: &mut CiphertextCache = zelf.as_opaque_type_mut()?;

    let ct_computable = ct.computable()
        .context("Self not computable")?;
    let other_computable = other.take_ciphertext()
        .context("Ciphertext not computable")?;

    *ct_computable += other_computable;

    Ok(SysCallResult::None)
}

pub fn ciphertext_sub_ct(zelf: FnInstance, mut params: FnParams, _: &ModuleMetadata<'_>, _: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let mut zelf = zelf?;

    let other: CiphertextCache = params.remove(0)
        .into_owned()
        .into_opaque_type()?;

    let ct: &mut CiphertextCache = zelf.as_opaque_type_mut()?;

    let ct_computable = ct.computable()
        .context("Self not computable")?;
    let other_computable = other.take_ciphertext()
        .context("Ciphertext not computable")?;

    *ct_computable -= other_computable;

    Ok(SysCallResult::None)
}

pub fn ciphertext_add_scalar(zelf: FnInstance, mut params: FnParams, _: &ModuleMetadata<'_>, _: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let mut zelf = zelf?;

    let scalar: OpaqueScalar = params.remove(0)
        .into_owned()
        .into_opaque_type()?;

    let ct: &mut CiphertextCache = zelf.as_opaque_type_mut()?;

    let ct_computable = ct.computable()
        .context("Self not computable")?;

    *ct_computable += scalar.0;

    Ok(SysCallResult::None)
}

pub fn ciphertext_sub_scalar(zelf: FnInstance, mut params: FnParams, _: &ModuleMetadata<'_>, _: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let mut zelf = zelf?;

    let scalar: OpaqueScalar = params.remove(0)
        .into_owned()
        .into_opaque_type()?;

    let ct: &mut CiphertextCache = zelf.as_opaque_type_mut()?;

    let ct_computable = ct.computable()
        .context("Self not computable")?;

    *ct_computable -= scalar.0;

    Ok(SysCallResult::None)
}

pub fn ciphertext_zero(_: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, _: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let ciphertext = CiphertextCache::Decompressed(Some(CompressedCiphertext::zero()), Ciphertext::zero());
    Ok(SysCallResult::Return(Primitive::Opaque(ciphertext.into()).into()))
}

pub fn ciphertext_commitment(zelf: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, _: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let mut zelf = zelf?;
    let zelf: &mut CiphertextCache = zelf.as_opaque_type_mut()?;
    let commitment = zelf.decompressed()
        .context("Ciphertext not decompressed")?
        .commitment()
        .as_point()
        .clone();

    Ok(SysCallResult::Return(OpaqueRistrettoPoint::Decompressed(None, commitment).into()))
}

pub fn ciphertext_handle(zelf: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, _: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let mut zelf = zelf?;
    let zelf: &mut CiphertextCache = zelf.as_opaque_type_mut()?;
    let handle = zelf.decompressed()
        .context("Ciphertext not decompressed")?
        .handle()
        .as_point()
        .clone();

    Ok(SysCallResult::Return(OpaqueRistrettoPoint::Decompressed(None, handle).into()))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::hash_map::DefaultHasher,
        hash::Hasher,
    };

    use super::*;

    fn opaque_hash(value: &CiphertextCache) -> u64 {
        let mut hasher = DefaultHasher::new();
        value.dyn_hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn ciphertext_dyn_hash_uses_ciphertext_bytes() {
        let first = CiphertextCache::Decompressed(Some(CompressedCiphertext::zero()), Ciphertext::zero());
        let second = CiphertextCache::Compressed(CompressedCiphertext::zero());
        let third = CiphertextCache::Decompressed(None, Ciphertext::new(PedersenCommitment::from_point(curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT), DecryptHandle::from_point(curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT)));

        assert_eq!(opaque_hash(&first), opaque_hash(&second));
        assert_ne!(opaque_hash(&first), opaque_hash(&third));
    }
}
