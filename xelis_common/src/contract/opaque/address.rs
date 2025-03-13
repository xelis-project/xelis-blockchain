use xelis_vm::{
    traits::Serializable,
    Context,
    EnvironmentError,
    FnInstance,
    FnParams,
    FnReturnType,
    OpaqueWrapper,
    Primitive,
    ValueCell
};
use crate::crypto::Address;

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

pub fn address_is_mainnet(zelf: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    let address: &Address = zelf?.as_opaque_type()?;
    Ok(Some(Primitive::Boolean(address.is_mainnet()).into()))
}

pub fn address_is_normal(zelf: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    let address: &Address = zelf?.as_opaque_type()?;
    Ok(Some(Primitive::Boolean(address.is_normal()).into()))
}

pub fn address_public_key_bytes(zelf: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    let address: &Address = zelf?.as_opaque_type()?;
    let bytes = address.get_public_key()
        .as_bytes()
        .into_iter()
        .map(|b| Primitive::U8(*b).into())
        .collect();

    Ok(Some(ValueCell::Array(bytes)))
}

pub fn address_from_string(_: FnInstance, mut params: FnParams, _: &mut Context) -> FnReturnType {
    let param = params.remove(0)
        .into_owned()?;
    let string = param.as_string()?;

    let address = Address::from_string(string)
        .map_err(|_| EnvironmentError::InvalidParameter)?;

    Ok(Some(Primitive::Opaque(OpaqueWrapper::new(address)).into()))
}