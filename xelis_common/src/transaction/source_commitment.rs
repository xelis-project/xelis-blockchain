use std::hash;

use schemars::JsonSchema;
use serde::{Serialize, Deserialize};

use crate::{
    serializer::*,
    crypto::{
        elgamal::CompressedCommitment,
        Hash,
        proofs::CommitmentEqProof
    }
};

// SourceCommitment is a structure that holds the commitment and the equality proof
// of the commitment to the asset
// In a transaction, every spendings are summed up in a single commitment per asset
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct SourceCommitment {
    commitment: CompressedCommitment,
    proof: CommitmentEqProof,
    asset: Hash,
}

// Implement Hash on SourceCommitment
// Note that we only have one SourceCommitment per asset
// So we only need to hash the asset
impl hash::Hash for SourceCommitment {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.asset.hash(state);
    }
}

impl SourceCommitment {
    /// Create a new SourceCommitment
    pub fn new(commitment: CompressedCommitment, proof: CommitmentEqProof, asset: Hash) -> Self {
        SourceCommitment {
            commitment,
            proof,
            asset
        }
    }

    // Get the commitment
    #[inline]
    pub fn get_commitment(&self) -> &CompressedCommitment {
        &self.commitment
    }

    // Get the equality proof
    #[inline]
    pub fn get_proof(&self) -> &CommitmentEqProof {
        &self.proof
    }

    // Get the asset hash
    #[inline]
    pub fn get_asset(&self) -> &Hash {
        &self.asset
    }
}

impl Serializer for SourceCommitment {
    fn write(&self, writer: &mut Writer) {
        self.commitment.write(writer);
        self.proof.write(writer);
        self.asset.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<SourceCommitment, ReaderError> {
        let commitment = CompressedCommitment::read(reader)?;
        let proof = CommitmentEqProof::read(reader)?;
        let asset = Hash::read(reader)?;

        Ok(SourceCommitment {
            commitment,
            proof,
            asset
        })
    }

    fn size(&self) -> usize {
        self.commitment.size() + self.proof.size() + self.asset.size()
    }
}