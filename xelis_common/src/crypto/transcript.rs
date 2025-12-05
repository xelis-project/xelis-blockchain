use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar, traits::IsIdentity};
use merlin::Transcript;
use thiserror::Error;

use super::{
    elgamal::{CompressedCiphertext, CompressedCommitment, CompressedHandle, CompressedPublicKey},
    Hash
};

#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum TranscriptError {
    #[error("point should not be the identity")]
    IdentityPoint,
}

pub trait ProtocolTranscript {
    fn append_scalar(&mut self, label: &[u8], scalar: &Scalar);
    fn append_point(&mut self, label: &[u8], point: &CompressedRistretto);
    fn append_public_key(&mut self, label: &[u8], point: &CompressedPublicKey);
    fn append_ciphertext(&mut self, label: &[u8], point: &CompressedCiphertext);
    fn append_commitment(&mut self, label: &[u8], point: &CompressedCommitment);
    fn append_handle(&mut self, label: &[u8], point: &CompressedHandle);
    fn append_hash(&mut self, label: &[u8], point: &Hash);

    fn challenge_scalar(&mut self, label: &[u8]) -> Scalar;

    fn validate_and_append_point(&mut self, label: &[u8], point: &CompressedRistretto) -> Result<(), TranscriptError>;

    fn equality_proof_domain_separator(&mut self);
    fn new_commitment_eq_proof_domain_separator(&mut self);
    fn transfer_proof_domain_separator(&mut self);
    fn deposit_proof_domain_separator(&mut self);
    fn burn_proof_domain_separator(&mut self);
    fn multisig_proof_domain_separator(&mut self);
    fn invoke_contract_proof_domain_separator(&mut self);
    fn deploy_contract_proof_domain_separator(&mut self);
    fn invoke_constructor_proof_domain_separator(&mut self);
    fn ciphertext_validity_proof_domain_separator(&mut self);
    fn balance_proof_domain_separator(&mut self);
    fn ownership_proof_domain_separator(&mut self);
    fn arbitrary_range_proof_domain_separator(&mut self);
}

impl ProtocolTranscript for Transcript {
    fn append_scalar(&mut self, label: &[u8], scalar: &Scalar) {
        self.append_message(label, scalar.as_bytes());
    }

    fn append_point(&mut self, label: &[u8], point: &CompressedRistretto) {
        self.append_message(label, point.as_bytes());
    }

    fn challenge_scalar(&mut self, label: &[u8]) -> Scalar {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);

        Scalar::from_bytes_mod_order_wide(&buf)
    }

    fn append_public_key(&mut self, label: &[u8], pubkey: &CompressedPublicKey) {
        self.append_message(label, pubkey.as_bytes());
    }

    fn append_ciphertext(&mut self, label: &[u8], ciphertext: &CompressedCiphertext) {
        self.append_message(label, &ciphertext.to_bytes());
    }

    fn append_commitment(&mut self, label: &[u8], commitment: &CompressedCommitment) {
        self.append_message(label, commitment.as_bytes());
    }

    fn append_handle(&mut self, label: &[u8], handle: &CompressedHandle) {
        self.append_message(label, handle.as_bytes());
    }

    fn append_hash(&mut self, label: &[u8], point: &Hash) {
        self.append_message(label, point.as_bytes())
    }

    fn validate_and_append_point(&mut self, label: &[u8], point: &CompressedRistretto) -> Result<(), TranscriptError> {
        if point.is_identity() {
            Err(TranscriptError::IdentityPoint)
        } else {
            self.append_message(label, point.as_bytes());
            Ok(())
        }
    }

    // domain separators

    fn new_commitment_eq_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"new-commitment-proof");
    }

    fn transfer_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"transfer-proof");
    }

    fn deposit_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"deposit-proof");
    }

    fn burn_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"burn-proof");
    }


    fn multisig_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"multisig-proof");
    }

    fn invoke_contract_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"invoke-contract-proof");
    }

    fn deploy_contract_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"deploy-contract-proof");
    }

    fn invoke_constructor_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"invoke-constructor-proof");
    }

    fn equality_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"equality-proof");
    }

    fn ciphertext_validity_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"validity-proof");
    }

    fn balance_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"balance-proof");
    }

    fn ownership_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"ownership-proof");
    }

    fn arbitrary_range_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"arbitrary-range-proof");
    }
}
