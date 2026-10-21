use matriochka::ResultExt;
use xelis_vm::{
    ValueCell,
    traits::DynSerializable,
    VMContext,
    EnvironmentError,
    FnInstance,
    FnParams,
    FnReturnType,
    Primitive,
    SysCallResult,
};

use crate::{
    contract::{ModuleMetadata, ContractMetadata, OpaqueRistrettoPoint, SIGNATURE_OPAQUE_ID},
    crypto::{Signature, SIGNATURE_SIZE},
    serializer::{Error as SerializationError, Serializer, Writer},
};

impl DynSerializable for Signature {
    fn get_size(&self) -> usize {
        SIGNATURE_SIZE
    }

    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializationError> {
        let start = buffer.len();
        let mut writer = Writer::new(&mut *buffer);
        SIGNATURE_OPAQUE_ID.write(&mut writer)?;
        self.write(&mut writer)?;
        Ok(buffer.len() - start)
    }
}

pub fn signature_from_bytes_fn(_: FnInstance, params: FnParams, _: &ModuleMetadata<'_>, _: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let bytes = params[0]
        .as_ref()
        .as_bytes()?;

    if bytes.len() != SIGNATURE_SIZE {
        return Err(EnvironmentError::InvalidParameter);
    }

    let signature = Signature::from_bytes(&bytes)
        .context("signature from bytes")?;
    Ok(SysCallResult::Return(ValueCell::Opaque(signature.into()).into()))
}

pub fn signature_verify_fn(zelf: FnInstance, mut params: FnParams, _: &ModuleMetadata<'_>, context: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    let signature: &Signature = zelf.as_opaque_type()?;

    let mut point: OpaqueRistrettoPoint = params.remove(1)
        .into_owned()
        .into_opaque_type()?;

    let data = params[0]
        .as_ref()
        .as_bytes()?;

    context.increase_gas_usage(data.len() as u64 * 2)?;

    let (compressed, key) = point.both()?;
    Ok(SysCallResult::Return(Primitive::Boolean(signature.verify_internal(&data, &key, compressed)).into()))
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::Scalar;
    use super::*;

    #[test]
    fn test_serde() {
        let signature = Signature::new(Scalar::from(1u64), Scalar::from(2u64));
        let v = serde_json::to_value(&signature).unwrap();

        let signature2: Signature = serde_json::from_value(v)
            .unwrap();

        assert_eq!(signature, signature2);
    }
}