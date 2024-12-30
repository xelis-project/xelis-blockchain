use std::any::TypeId;
use xelis_builder::ConstFnParams;
use xelis_vm::{traits::Serializable, Constant, Context, FnInstance, FnParams, FnReturnType, Opaque, OpaqueWrapper, Value, ValueCell};
use crate::crypto::Address;

use super::{Serializer, Writer, ADDRESS_OPAQUE_ID};

impl Serializable for Address {
    fn serialize(&self, buffer: &mut Vec<u8>) -> usize {
        let mut writer = Writer::new(buffer);
        writer.write_u8(ADDRESS_OPAQUE_ID);
        self.write(&mut writer);
        writer.total_write()
    }
}

impl Opaque for Address {
    fn get_type(&self) -> TypeId {
        TypeId::of::<Address>()
    }

    fn display(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Address({})", self)
    }

    fn clone_box(&self) -> Box<dyn Opaque> {
        Box::new(self.clone())
    }
}

pub fn address_is_mainnet(zelf: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    let address: &Address = zelf?.as_opaque_type()?;
    Ok(Some(Value::Boolean(address.is_mainnet()).into()))
}

pub fn address_is_normal(zelf: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    let address: &Address = zelf?.as_opaque_type()?;
    Ok(Some(Value::Boolean(address.is_normal()).into()))
}

pub fn address_public_key_bytes(zelf: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    let address: &Address = zelf?.as_opaque_type()?;
    let bytes = address.get_public_key().as_bytes().into_iter().map(|b| Value::U8(*b).into()).collect();
    Ok(Some(ValueCell::Array(bytes)))
}

pub fn address_from_string(params: ConstFnParams) -> Result<Constant, anyhow::Error> {
    let addr = params[0].as_string()?;
    let addr = Address::from_string(addr)?;

    Ok(Constant::Default(Value::Opaque(OpaqueWrapper::new(addr))))
}