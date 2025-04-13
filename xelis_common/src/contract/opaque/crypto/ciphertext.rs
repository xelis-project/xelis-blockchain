use std::hash::Hasher;

use anyhow::Context as AnyhowContext;
use curve25519_dalek::Scalar;
use xelis_vm::{impl_opaque, traits::{DynHash, Serializable}, Context, FnInstance, FnParams, FnReturnType};
use crate::{
    account::CiphertextCache,
    contract::CIPHERTEXT_OPAQUE_ID,
    crypto::elgamal::RISTRETTO_COMPRESSED_SIZE,
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
    fn dyn_hash(&self, _: &mut dyn Hasher) {
        // nothing
    }
}

impl_opaque!(
    "Ciphertext",
    CiphertextCache
);
impl_opaque!(
    "Ciphertext",
    CiphertextCache,
    json
);

pub fn ciphertext_mul_plaintext(zelf: FnInstance, mut params: FnParams, _: &mut Context) -> FnReturnType {
    let zelf: &mut CiphertextCache = zelf?.as_opaque_type_mut()?;
    let value = params.remove(0)
        .as_u64()?;

    let computable = zelf.computable()
        .context("Ciphertext not computable")?;

    *computable = &*computable * Scalar::from(value);

    Ok(None)
}

pub fn ciphertext_div_plaintext(zelf: FnInstance, mut params: FnParams, _: &mut Context) -> FnReturnType {
    let zelf: &mut CiphertextCache = zelf?.as_opaque_type_mut()?;
    let value = params.remove(0)
        .as_u64()?;

    if value == 0 {
        return Err(anyhow::anyhow!("Division by zero").into());
    }

    let computable = zelf.computable()
        .context("Ciphertext not computable")?;

    *computable = &*computable * Scalar::from(value).invert();

    Ok(None)
}

pub fn ciphertext_add_plaintext(zelf: FnInstance, mut params: FnParams, _: &mut Context) -> FnReturnType {
    let zelf: &mut CiphertextCache = zelf?.as_opaque_type_mut()?;
    let value = params.remove(0)
        .as_u64()?;

    let mut computable = zelf.computable()
        .context("Ciphertext not computable")?;

    computable += Scalar::from(value);

    Ok(None)
}

pub fn ciphertext_sub_plaintext(zelf: FnInstance, mut params: FnParams, _: &mut Context) -> FnReturnType {
    let zelf: &mut CiphertextCache = zelf?.as_opaque_type_mut()?;
    let value = params.remove(0)
        .as_u64()?;

    let mut computable = zelf.computable()
        .context("Ciphertext not computable")?;

    computable -= Scalar::from(value);

    Ok(None)
}
