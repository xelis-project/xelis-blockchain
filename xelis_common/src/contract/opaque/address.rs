use xelis_vm::{
    VMContext,
    EnvironmentError,
    FnInstance,
    FnParams,
    FnReturnType,
    OpaqueWrapper,
    Primitive,
    SysCallResult,
    ValueCell,
    traits::DynSerializable
};
use crate::{
    contract::{ContractMetadata, ModuleMetadata, OpaqueRistrettoPoint},
    crypto::{Address, NORMAL_ADDRESS_LEN},
    serializer::{Error as SerializationError, Serializer, Writer, WriterExt},
};

use super::ADDRESS_OPAQUE_ID;

impl DynSerializable for Address {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializationError> {
        let start = buffer.len();
        let mut writer = Writer::new(&mut *buffer);
        writer.write_u8(ADDRESS_OPAQUE_ID)?;
        self.write(&mut writer)?;
        Ok(buffer.len() - start)
    }

    fn get_size(&self) -> usize {
        1 + self.size()
    }
}

pub fn address_is_mainnet(zelf: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, _: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    let address: &Address = zelf.as_opaque_type()?;
    Ok(SysCallResult::Return(Primitive::Boolean(address.is_mainnet()).into()))
}

pub fn address_to_bytes(zelf: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, _: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    let address: &Address = zelf.as_opaque_type()?;
    Ok(SysCallResult::Return(ValueCell::Bytes(address.to_bytes()?).into()))
}

pub fn address_to_point(zelf: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, _: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    let address: &Address = zelf.as_opaque_type()?;
    let point = address.get_public_key()
        .as_point()
        .clone();

    Ok(SysCallResult::Return(OpaqueRistrettoPoint::Compressed(point).into()))
}

pub fn address_to_string(zelf: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, _: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    let address: &Address = zelf.as_opaque_type()?;
    Ok(SysCallResult::Return(Primitive::String(address.to_string()).into()))
}

pub fn address_from_string(_: FnInstance, mut params: FnParams, _: &ModuleMetadata<'_>, _: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let param = params.remove(0)
        .into_owned();
    let string = param.as_string()?;

    if string.len() > NORMAL_ADDRESS_LEN {
        return Err(EnvironmentError::InvalidParameter);
    }

    let address = Address::from_string(string)
        .map_err(|_| EnvironmentError::InvalidParameter)?;

    Ok(SysCallResult::Return(ValueCell::Opaque(OpaqueWrapper::new(address)).into()))
}

pub fn address_from_bytes(_: FnInstance, params: FnParams, _: &ModuleMetadata<'_>, _: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let bytes = params[0]
        .as_ref()
        .as_bytes()?;

    let address = Address::from_bytes(&bytes)
        .map_err(|_| EnvironmentError::InvalidParameter)?;

    Ok(SysCallResult::Return(ValueCell::Opaque(OpaqueWrapper::new(address)).into()))
}