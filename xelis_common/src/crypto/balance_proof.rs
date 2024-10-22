use curve25519_dalek::{ristretto::CompressedRistretto, Scalar};
use super::{
    elgamal::{
        Ciphertext,
        DecompressionError,
        PedersenCommitment
    },
    proofs::{ProofVerificationError, PC_GENS},
    PrivateKey
};

/// A balance proof is a cryptographic proof that a user has a certain amount in its balance.
/// It is used to prove that a user has enough money to make a transaction.
/// WARNING: Not audit-ready, this is a simple proof and should be used for testing purposes only.
/// It may be possible to build a fake proof.
pub struct BalanceProof {
    /// The expected balance amount.
    amount: u64,
    /// The decrypted handle such as `s * D` where s is the private key and D is the decrypt handle of the ciphertext.
    handle: CompressedRistretto,
}

impl BalanceProof {
    /// Create a new balance proof.
    pub fn new(amount: u64, handle: CompressedRistretto) -> Self {
        Self { amount, handle }
    }

    /// Prove the balance proof.
    pub fn prove(sk: &PrivateKey, amount: u64, ciphertext: &Ciphertext) -> Self {
        let handle = sk.as_scalar() * ciphertext.handle().as_point();
        Self::new(amount, handle.compress())
    }

    /// Verify the balance proof.
    pub fn verify(&self, commitment: &PedersenCommitment) -> Result<(), ProofVerificationError> {
        let handle = self.handle.decompress().ok_or(DecompressionError)?;
        let point = commitment.as_point();

        // Check if the handle is the same as the commitment.
        // This is a simple check to avoid fake proofs proving a 0 balance.
        if handle == *point {
            return Err(ProofVerificationError::GenericProof);
        }

        let calculated_point = point - handle;
        let expected_point = Scalar::from(self.amount) * PC_GENS.B;
        if calculated_point != expected_point {
            return Err(ProofVerificationError::GenericProof);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;

    fn test_proof(amount_prove: u64, amount_ct: u64) -> bool {
        let keypair = KeyPair::new();
        let ct = keypair.get_public_key().encrypt(amount_ct);

        let proof = BalanceProof::prove(keypair.get_private_key(), amount_prove, &ct);
        proof.verify(&ct.commitment()).is_ok()
    }

    #[test]
    fn test_balance_proof() {
        assert!(test_proof(100, 100));
    }

    #[test]
    fn test_invalid_balance_proof() {
        assert!(!test_proof(100, 200));
    }

    #[test]
    fn test_fake_balance_proof() {
        let keypair = KeyPair::new();
        let amount = 100u64;
        let ct = keypair.get_public_key().encrypt(amount);

        let proof = BalanceProof::prove(keypair.get_private_key(), amount, &ct);
        assert!(proof.verify(&ct.commitment()).is_ok());

        // Try a fake proof of 0 balance while we know the balance is 100.
        let fake_proof = BalanceProof::new(0, ct.commitment().as_point().compress());
        assert!(fake_proof.verify(&ct.commitment()).is_err());

        // Try to generate a proof on another ciphertext that don't use the same opening.
        let ct_2 = keypair.get_public_key().encrypt(amount);
        let fake_proof = BalanceProof::prove(keypair.get_private_key(), amount, &ct_2);
        assert!(fake_proof.verify(&ct.commitment()).is_err());
    }
}