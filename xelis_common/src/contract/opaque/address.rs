use xelis_vm::{
    RuntimeValue,
    Heap,
    VMContext,
    EnvironmentError,
    FnInstance,
    FnParams,
    FnReturnType,
    Primitive,
    SysCallResult,
    traits::DynSerializable
};
use crate::{
    contract::{ContractMetadata, ModuleMetadata, OpaqueRistrettoPoint},
    crypto::{Address, NORMAL_ADDRESS_LEN},
    serializer::{Error as SerializationError, Serializer, Writer},
};

use super::ADDRESS_OPAQUE_ID;

impl DynSerializable for Address {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializationError> {
        let start = buffer.len();
        let mut writer = Writer::new(&mut *buffer);
        ADDRESS_OPAQUE_ID.write(&mut writer)?;
        self.write(&mut writer)?;
        Ok(buffer.len() - start)
    }

    fn get_size(&self) -> usize {
        1 + self.size()
    }
}

pub fn address_is_mainnet(zelf: FnInstance, _: FnParams<'_>, _: &ModuleMetadata<'_>, _: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    heap.with_value(zelf, |zelf, _heap| {
        let address: &Address = zelf.as_opaque_type()?;
        Ok(SysCallResult::Return(Primitive::Boolean(address.is_mainnet()).into()))
    })
}

pub fn address_to_bytes(zelf: FnInstance, _: FnParams<'_>, _: &ModuleMetadata<'_>, _: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    heap.with_value(zelf, |zelf, _heap| {
        let address: &Address = zelf.as_opaque_type()?;
        Ok(SysCallResult::Return(RuntimeValue::Bytes(address.to_bytes()?).into()))
    })
}

pub fn address_to_point(zelf: FnInstance, _: FnParams<'_>, _: &ModuleMetadata<'_>, _: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    heap.with_value(zelf, |zelf, _heap| {
        let address: &Address = zelf.as_opaque_type()?;
        let point = address.get_public_key()
            .as_point()
            .clone();

        Ok(SysCallResult::Return(OpaqueRistrettoPoint::Compressed(point).into()))
    })
}

pub fn address_to_string(zelf: FnInstance, _: FnParams<'_>, _: &ModuleMetadata<'_>, _: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    heap.with_value(zelf, |zelf, _heap| {
        let address: &Address = zelf.as_opaque_type()?;
        Ok(SysCallResult::Return(Primitive::String(address.to_string()).into()))
    })
}

pub fn address_from_string(_: FnInstance, params: FnParams<'_>, _: &ModuleMetadata<'_>, _: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let param = params.remove(0).into_owned(heap)?;
    let string = param.as_string()?;

    if string.len() > NORMAL_ADDRESS_LEN {
        return Err(EnvironmentError::InvalidParameter);
    }

    let address = Address::from_string(string)
        .map_err(|_| EnvironmentError::InvalidParameter)?;

    Ok(SysCallResult::Return(RuntimeValue::Opaque(address.into()).into()))
}

pub fn address_from_bytes(_: FnInstance, params: FnParams<'_>, _: &ModuleMetadata<'_>, _: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let bytes = params[0]
        .as_ref(heap)
        .as_bytes()?;

    let address = Address::from_bytes(&bytes)
        .map_err(|_| EnvironmentError::InvalidParameter)?;

    Ok(SysCallResult::Return(RuntimeValue::Opaque(address.into()).into()))
}