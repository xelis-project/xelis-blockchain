
use bulletproofs::RangeProof;
use serde::{Deserialize, Serialize};
use xelis_vm::{
    Heap,
    Opaque,
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
    contract::{
        opaque::RANGE_PROOF_OPAQUE_ID,
        ContractMetadata,
        ModuleMetadata,
        OpaqueRistrettoPoint,
        OpaqueTranscript
    },
    crypto::proofs::{BP_GENS, PC_GENS},
    transaction::MAX_TRANSFER_COUNT,
    serializer::{Error as SerializationError, *},
};

pub const GAS_PER_COMMITMENT_BIT: u64 = 70_000;

#[derive(Debug, Clone, Serialize, Deserialize, Opaque)]
#[opaque(name = "RangeProof", json, serializable)]
pub struct RangeProofWrapper(pub RangeProof);

impl DynSerializable for RangeProofWrapper {
    fn get_size(&self) -> Result<usize, SerializationError> {
        Ok(self.0.size())
    }

    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializationError> {
        let start = buffer.len();
        let mut writer = Writer::new(&mut *buffer);
        RANGE_PROOF_OPAQUE_ID.write(&mut writer)?;
        self.0.write(&mut writer)?;
        Ok(buffer.len() - start)
    }
}

pub fn range_proof_verify_single(zelf: FnInstance, params: FnParams<'_>, _: &ModuleMetadata<'_>, context: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    heap.with_value(zelf, |zelf, heap| {
        
        let proof_size = params[2].as_ref(heap)
            .as_u8()?;

        if proof_size == 0 || proof_size > 64 {
            return Err(EnvironmentError::Static("proof size must be between 1 and 64"));
        }

        context.increase_gas_usage(proof_size as u64 * GAS_PER_COMMITMENT_BIT)?;

        // support pre-1.86 rustc, which doesn't support get_disjoint_mut([0, 1])
        let (left, right) = {
            let (left, right) = params.split_at_mut(1);
            (&mut left[0], &mut right[0])
        };

        let commitment = {
                let commitment: &mut OpaqueRistrettoPoint = left
                    .as_mut(heap)
                    .as_opaque_type_mut()?;

                let (compressed, decompressed) = commitment.both(context)?;
                (decompressed.clone(), compressed.clone())
        };

        let transcript: &mut OpaqueTranscript = right
            .as_mut(heap)
            .as_opaque_type_mut()?;

        let zelf: &RangeProofWrapper = zelf.as_opaque_type()?;

        let valid = zelf.0.verify_single(&BP_GENS, &PC_GENS, &mut transcript.0, &commitment, proof_size as usize)
            .is_ok();

        Ok(SysCallResult::Return(Primitive::Boolean(valid).into()))
    })
}

pub fn range_proof_verify_multiple(zelf: FnInstance, params: FnParams<'_>, _: &ModuleMetadata<'_>, context: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    heap.with_value(zelf, |zelf, heap| {
        let mut tmp = params[0]
            .as_mut(heap)
            .as_mut_vec()?.clone();

        let count = tmp.len();
        let bits = params[2].as_ref(heap).as_u8()?;
        // Validate dimensions before touching the generators or decompressing
        // commitments. The generator set supports at most 512 parties.
        if !count.is_power_of_two() || count > MAX_TRANSFER_COUNT * 2 + 2 {
            return Err(EnvironmentError::Static("commitment count must be a nonzero power of two within generator capacity"));
        }

        if !matches!(bits, 8 | 16 | 32 | 64) {
            return Err(EnvironmentError::Static("proof size must be 8, 16, 32 or 64"));
        }

        // Dimensions are bounded above, so this multiplication cannot overflow.
        let gas = count as u64 * bits as u64 * GAS_PER_COMMITMENT_BIT;

        context.increase_gas_usage(gas)?;

        let commitments = {
            tmp.iter_mut()
            .map(|p| {
                let opaque: &mut OpaqueRistrettoPoint = p.as_mut(heap)
                    .as_opaque_type_mut()?;
                let (compressed, point) = opaque.both(context)?;
                Ok((point.clone(), compressed.clone()))
            })
            .collect::<Result<Vec<_>, EnvironmentError>>()?
        };

        let proof_size = params[2].as_ref(heap)
            .as_u8()?;

        if proof_size == 0 || proof_size > 64 {
            return Err(EnvironmentError::Static("proof size must be between 1 and 64"));
        }

        let transcript: &mut OpaqueTranscript = params[1]
            .as_mut(heap)
            .as_opaque_type_mut()?;

        let zelf: &RangeProofWrapper = zelf.as_opaque_type()?;

        let valid = zelf.0.verify_multiple(&BP_GENS, &PC_GENS, &mut transcript.0, &commitments, proof_size as usize)
            .is_ok();

        Ok(SysCallResult::Return(Primitive::Boolean(valid).into()))
    })
}