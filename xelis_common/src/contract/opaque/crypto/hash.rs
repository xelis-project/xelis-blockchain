use matriochka::ResultExt;
use sha3::{Digest, Sha3_256};
use xelis_vm::{
    RuntimeValue,
    Heap,
    PrimitiveInteger,
    traits::DynSerializable,
    VMContext,
    EnvironmentError,
    FnInstance,
    FnParams,
    FnReturnType,
    Primitive,
    SysCallResult,
    U256
};
use crate::{
    contract::{ModuleMetadata, ContractMetadata, HASH_OPAQUE_ID},
    crypto::{hash, Hash, HASH_SIZE},
    serializer::{Error as SerializationError, Serializer, Writer},
};

impl DynSerializable for Hash {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializationError> {
        let start = buffer.len();
        let mut writer = Writer::new(&mut *buffer);
        HASH_OPAQUE_ID.write(&mut writer)?;
        self.write(&mut writer)?;
        Ok(buffer.len() - start)
    }

    fn get_size(&self) -> usize {
        HASH_SIZE
    }
}

pub fn hash_to_bytes_fn(zelf: FnInstance, _: FnParams<'_>, _: &ModuleMetadata<'_>, _: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    heap.with_value(zelf, |zelf, _heap| {
        let hash: &Hash = zelf.as_opaque_type()?;
        let bytes = RuntimeValue::Bytes(hash.as_bytes().into());
        Ok(SysCallResult::Return(bytes.into()))
    })
}

pub fn hash_to_array_fn(zelf: FnInstance, _: FnParams<'_>, _: &ModuleMetadata<'_>, _: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    heap.with_value(zelf, |zelf, heap| {
        let hash: &Hash = zelf.as_opaque_type()?;
        let bytes = hash.as_bytes()
            .into_iter()
            .map(|b| heap.insert(Primitive::Integer(PrimitiveInteger::U8(*b)).into()))
            .collect();

        Ok(SysCallResult::Return(RuntimeValue::Object(bytes).into()))
    })
}

pub fn hash_from_bytes_fn(_: FnInstance, params: FnParams<'_>, _: &ModuleMetadata<'_>, _: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let param = params.remove(0);
    let bytes = param.as_bytes(heap)?;

    if bytes.len() != HASH_SIZE {
        return Err(EnvironmentError::InvalidParameter);
    }

    let hash = Hash::from_bytes(&bytes)
        .context("failed to create hash from bytes")?;

    Ok(SysCallResult::Return(RuntimeValue::Opaque(hash.into()).into()))
}

pub fn hash_from_array_fn(_: FnInstance, params: FnParams<'_>, _: &ModuleMetadata<'_>, _: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let param = params.remove(0);
    let values = param.as_vec(heap)?;

    if values.len() != HASH_SIZE {
        return Err(EnvironmentError::InvalidParameter);
    }

    let bytes = values.into_iter()
        .map(|v| v.as_ref(heap).as_u8())
        .collect::<Result<Vec<_>, _>>()?;

    let hash = Hash::from_bytes(&bytes)
        .context("failed to create hash from bytes")?;

    Ok(SysCallResult::Return(RuntimeValue::Opaque(hash.into()).into()))
}

pub fn hash_from_u256_fn(_: FnInstance, params: FnParams<'_>, _: &ModuleMetadata<'_>, _: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let param = params.remove(0);

    let value = param.as_u256(heap)?;
    let hash = Hash::from_bytes(&value.to_be_bytes())
        .context("failed to create hash from u256 be bytes")?;

    Ok(SysCallResult::Return(RuntimeValue::Opaque(hash.into()).into()))
}

pub fn hash_to_u256_fn(zelf: FnInstance, _: FnParams<'_>, _: &ModuleMetadata<'_>, _: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    heap.with_value(zelf, |zelf, _heap| {
        let hash: &Hash = zelf.as_opaque_type()?;
        Ok(SysCallResult::Return(Primitive::Integer(PrimitiveInteger::U256(U256::from_be_bytes(*hash.as_bytes()))).into()))
    })
}

pub fn hash_to_hex_fn(zelf: FnInstance, _: FnParams<'_>, _: &ModuleMetadata<'_>, _: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    heap.with_value(zelf, |zelf, _heap| {
        let hash: &Hash = zelf.as_opaque_type()?;
        Ok(SysCallResult::Return(Primitive::String(hex::encode(hash.as_bytes())).into()))
    })
}

pub fn hash_from_hex_fn(_: FnInstance, params: FnParams<'_>, _: &ModuleMetadata<'_>, _: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let param = params.remove(0);
    let hex = param.as_string(heap)?;

    if hex.len() != HASH_SIZE * 2 {
        return Err(EnvironmentError::InvalidParameter);
    }

    let hash = Hash::from_hex(hex)
        .context("failed to create hash from hex")?;

    Ok(SysCallResult::Return(RuntimeValue::Opaque(hash.into()).into()))
}

pub fn hash_zero_fn(_: FnInstance, _: FnParams<'_>, _: &ModuleMetadata<'_>, _: &mut VMContext, _heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let hash = Hash::zero();
    Ok(SysCallResult::Return(RuntimeValue::Opaque(hash.into()).into()))
}

pub fn hash_max_fn(_: FnInstance, _: FnParams<'_>, _: &ModuleMetadata<'_>, _: &mut VMContext, _heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let hash = Hash::max();
    Ok(SysCallResult::Return(RuntimeValue::Opaque(hash.into()).into()))
}

pub fn blake3_fn(_: FnInstance, params: FnParams<'_>, _: &ModuleMetadata<'_>, context: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let input = params[0]
        .as_ref(heap)
        .as_bytes()?;

    // Blake3 is relatively cheap
    // Gas cost is proportional to input size
    context.increase_gas_usage(input.len() as u64)?;

    let hash = hash(&input);
    Ok(SysCallResult::Return(RuntimeValue::Opaque(hash.into()).into()))
}

pub fn sha3_fn(_: FnInstance, params: FnParams<'_>, _: &ModuleMetadata<'_>, context: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let input = params[0]
        .as_ref(heap)
        .as_bytes()?;

    // SHA256 is more expensive
    // Gas cost is proportional to input size
    context.increase_gas_usage((input.len() as u64) * 4)?;

    let hash = Hash::new(Sha3_256::digest(&input).into());
    Ok(SysCallResult::Return(RuntimeValue::Opaque(hash.into()).into()))
}
