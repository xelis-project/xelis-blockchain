use xelis_vm::{
    traits::Serializable,
    Context,
    EnvironmentError,
    FnInstance,
    FnParams,
    FnReturnType,
    OpaqueWrapper,
    Primitive,
    SysCallResult,
};
use crate::{
    contract::{ContractMetadata, ModuleMetadata, OpaqueRistrettoPoint},
    crypto::Address
};

use super::{Serializer, Writer, ADDRESS_OPAQUE_ID};

impl Serializable for Address {
    fn serialize(&self, buffer: &mut Vec<u8>) -> usize {
        let mut writer = Writer::new(buffer);
        writer.write_u8(ADDRESS_OPAQUE_ID);
        self.write(&mut writer);
        writer.total_write()
    }

    fn get_size(&self) -> usize {
        1 + self.size()
    }

    fn is_serializable(&self) -> bool {
        true
    }
}

pub fn address_is_mainnet(zelf: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, _: &mut Context) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    let address: &Address = zelf.as_opaque_type()?;
    Ok(SysCallResult::Return(Primitive::Boolean(address.is_mainnet()).into()))
}

pub fn address_is_normal(zelf: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, _: &mut Context) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    let address: &Address = zelf.as_opaque_type()?;
    Ok(SysCallResult::Return(Primitive::Boolean(address.is_normal()).into()))
}

pub fn address_to_point(zelf: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, _: &mut Context) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    let address: &Address = zelf.as_opaque_type()?;
    let point = address.get_public_key()
        .as_point()
        .clone();

    Ok(SysCallResult::Return(OpaqueRistrettoPoint::Compressed(point).into()))
}

pub fn address_from_string(_: FnInstance, mut params: FnParams, _: &ModuleMetadata<'_>, _: &mut Context) -> FnReturnType<ContractMetadata> {
    let param = params.remove(0)
        .into_owned();
    let string = param.as_string()?;

    let address = Address::from_string(string)
        .map_err(|_| EnvironmentError::InvalidParameter)?;

    Ok(SysCallResult::Return(Primitive::Opaque(OpaqueWrapper::new(address)).into()))
}