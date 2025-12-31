use curve25519_dalek::{
    ristretto::CompressedRistretto,
    traits::{IsIdentity, VartimeMultiscalarMul},
    RistrettoPoint,
    Scalar
};
use merlin::Transcript;
use rand::rngs::OsRng;
use schemars::JsonSchema;
use zeroize::Zeroize;

use crate::{
    crypto::{
        elgamal::{
            DecompressionError,
            DecryptHandle,
            PedersenCommitment,
            PedersenOpening,
            PublicKey,
            RISTRETTO_COMPRESSED_SIZE,
            SCALAR_SIZE
        },
        ProtocolTranscript
    },
    serializer::{
        Reader,
        ReaderError,
        Serializer,
        Writer
    },
    transaction::TxVersion
};
use super::{
    BatchCollector,
    ProofVerificationError,
    PC_GENS,
    G,
    H,
};

/// Cipher text validity proof.
/// This proof is used to prove that a given ciphertext is valid and was created correctly for the right recipient.
#[allow(non_snake_case)]
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, JsonSchema)]
pub struct CiphertextValidityProof {
    #[schemars(with = "Vec<u8>")]
    Y_0: CompressedRistretto,
    #[schemars(with = "Vec<u8>")]
    Y_1: CompressedRistretto,
    #[schemars(with = "Option<Vec<u8>>")]
    Y_2: Option<CompressedRistretto>,
    #[schemars(with = "Vec<u8>")]
    z_r: Scalar,
    #[schemars(with = "Vec<u8>")]
    z_x: Scalar,
}

#[allow(non_snake_case)]
impl CiphertextValidityProof {
    pub fn new(
        destination_pubkey: &PublicKey,
        source_pubkey: &PublicKey,
        amount: u64,
        opening: &PedersenOpening,
        tx_version: TxVersion,
        transcript: &mut Transcript,
    ) -> Self {
        transcript.ciphertext_validity_proof_domain_separator();

        let P_dest = destination_pubkey.as_point();

        let x = Scalar::from(amount);
        let r = opening.as_scalar();

        let mut y_r = Scalar::random(&mut OsRng);
        let mut y_x = Scalar::random(&mut OsRng);

        let Y_0 = PC_GENS.commit(y_x, y_r).compress();
        let Y_1 = (&y_r * P_dest).compress();

        let Y_2 = if tx_version >= TxVersion::V1 {
            Some((&y_r * source_pubkey.as_point()).compress())
        } else {
            None
        };

        transcript.append_point(b"Y_0", &Y_0);
        transcript.append_point(b"Y_1", &Y_1);
        if let Some(Y_2) = Y_2.as_ref() {
            transcript.append_point(b"Y_2", Y_2);
        }

        let c = transcript.challenge_scalar(b"c");

        // masked message and opening
        let z_r = &(&c * r) + &y_r;
        let z_x = &(&c * &x) + &y_x;

        if tx_version >= TxVersion::V2 {
            transcript.append_scalar(b"z_r", &z_r);
            transcript.append_scalar(b"z_x", &z_x);
        }

        transcript.challenge_scalar(b"w");

        y_r.zeroize();
        y_x.zeroize();

        Self { Y_0, Y_1, Y_2, z_r, z_x }
    }

    /// Pre-verification of the ciphertext validity proof.
    /// This function checks the validity of the proof without performing the full verification.
    /// It collects the necessary data for batch verification.
    pub fn pre_verify(
        &self,
        commitment: &PedersenCommitment,
        dest_pubkey: &PublicKey,
        sender_pubkey: &PublicKey,
        dest_handle: &DecryptHandle,
        sender_handle: &DecryptHandle,
        tx_version: TxVersion,
        transcript: &mut Transcript,
        batch_collector: &mut BatchCollector,
    ) -> Result<(), ProofVerificationError> {
        transcript.ciphertext_validity_proof_domain_separator();

        transcript.validate_and_append_point(b"Y_0", &self.Y_0)?;
        transcript.validate_and_append_point(b"Y_1", &self.Y_1)?;

        // Y_2 is mandatory starting v1
        if self.Y_2.is_some() != (tx_version >= TxVersion::V1) {
            return Err(ProofVerificationError::CiphertextValidityProof);
        }

        if let Some(Y_2) = self.Y_2.as_ref() {
            transcript.validate_and_append_point(b"Y_2", Y_2)?;
        }

        let c = transcript.challenge_scalar(b"c");
        if tx_version >= TxVersion::V2 {
            transcript.append_scalar(b"z_r", &self.z_r);
            transcript.append_scalar(b"z_x", &self.z_x);
        }

        let w = transcript.challenge_scalar(b"w");

        let w_negated = -&w;

        let Y_0 = self
            .Y_0
            .decompress()
            .ok_or(DecompressionError)?;
        let Y_1 = self
            .Y_1
            .decompress()
            .ok_or(DecompressionError)?;
        let Y_2 = if let Some(Y_2) = self.Y_2.as_ref() {
            Some(
                Y_2
                    .decompress()
                    .ok_or(DecompressionError)?,
            )
        } else {
            None
        };

        let P_dest = dest_pubkey.as_point();
        let P_source = sender_pubkey.as_point();

        let C = commitment.as_point();
        let D_dest = dest_handle.as_point();
        let D_source = sender_handle.as_point();

        let batch_factor = Scalar::random(&mut OsRng);

        // z_x * G
        batch_collector.g_scalar += self.z_x * batch_factor;
        // z_r * H
        batch_collector.h_scalar += self.z_r * batch_factor;

        let w_z_r = w * self.z_r;
        let w_negated_c = w_negated * c;
        batch_collector.dynamic_scalars.extend(
            [
                -c,            // -c
                -Scalar::ONE,  // -identity
                w_z_r,  // w * z_r
                w_negated_c, // -w * c
                w_negated,     // -w
            ]
            .map(|s| s * batch_factor),
        );
        batch_collector.dynamic_points.extend([
            C,      // C
            &Y_0,   // Y_0
            P_dest, // P_dest
            D_dest, // D_dest
            &Y_1,   // Y_1
        ]);

        if let Some(Y_2) = Y_2 {
            batch_collector.dynamic_scalars.extend([
                w * w_z_r,           // w * z_r
                w * w_negated_c, // -w * c
                w * w_negated,   // -w
            ].map(|s| s * batch_factor));

            batch_collector.dynamic_points.extend([
                P_source, // P_source
                D_source, // D_source
                &Y_2,     // Y_2
            ]);
        }

        Ok(())
    }

    /// Verify the ciphertext validity proof.
    /// This function checks the validity of the proof against the provided commitment and public keys.
    /// It directly verifys the proof without collecting data for batch verification.
    pub fn verify(
        &self,
        commitment: &PedersenCommitment,
        dest_pubkey: &PublicKey,
        source_pubkey: &PublicKey,
        dest_handle: &DecryptHandle,
        source_handle: &DecryptHandle,
        transcript: &mut Transcript,
    ) -> Result<(), ProofVerificationError> {
        transcript.ciphertext_validity_proof_domain_separator();

        transcript.validate_and_append_point(b"Y_0", &self.Y_0)?;
        transcript.validate_and_append_point(b"Y_1", &self.Y_1)?;

        let Y_2 = self.Y_2.as_ref().ok_or(ProofVerificationError::Format)?;
        transcript.validate_and_append_point(b"Y_2", Y_2)?;

        let c = transcript.challenge_scalar(b"c");

        transcript.append_scalar(b"z_r", &self.z_r);
        transcript.append_scalar(b"z_x", &self.z_x);

        let w = transcript.challenge_scalar(b"w");

        let ww = &w * &w;

        let w_negated = -&w;
        let ww_negated = -&ww;

        // check the required algebraic conditions
        let Y_0 = self
            .Y_0
            .decompress()
            .ok_or(DecompressionError)?;
        let Y_1 = self
            .Y_1
            .decompress()
            .ok_or(DecompressionError)?;
        let Y_2 = Y_2.decompress()
            .ok_or(DecompressionError)?;

        let P_dest = dest_pubkey.as_point();
        let P_source = source_pubkey.as_point();

        let C = commitment.as_point();
        let D_dest = dest_handle.as_point();
        let D_source = source_handle.as_point();

        let check = RistrettoPoint::vartime_multiscalar_mul(
            vec![
                &self.z_r,           // z_r
                &self.z_x,           // z_x
                &(-&c),              // -c
                &-(&Scalar::ONE),    // -identity
                &(&w * &self.z_r),   // w * z_r
                &(&w_negated * &c),  // -w * c
                &w_negated,          // -w
                &(&ww * &self.z_r),  // ww * z_r
                &(&ww_negated * &c), // -ww * c
                &ww_negated,         // -ww
            ],
            vec![
                &(*H), // H
                &(*G), // G
                C,        // C
                &Y_0,     // Y_0
                P_dest,  // P_first
                D_dest,  // D_first
                &Y_1,     // Y_1
                P_source, // P_second
                D_source, // D_second
                &Y_2, // Y_2
            ],
        );

        if check.is_identity() {
            Ok(())
        } else {
            Err(ProofVerificationError::CiphertextValidityProof)
        }
    }
}

#[allow(non_snake_case)]
impl Serializer for CiphertextValidityProof {
    fn write(&self, writer: &mut Writer) {
        self.Y_0.write(writer);
        self.Y_1.write(writer);
        if let Some(Y_2) = self.Y_2 {
            Y_2.write(writer);
        }
        self.z_r.write(writer);
        self.z_x.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let bit = reader.context()
            .get_optional::<TxVersion>()
            .map_or(true, |version| *version >= TxVersion::V1);

        let Y_0 = CompressedRistretto::read(reader)?;
        let Y_1 = CompressedRistretto::read(reader)?;
        let Y_2 = if bit {
            Some(CompressedRistretto::read(reader)?)
        } else {
            None
        };

        let z_r = Scalar::read(reader)?;
        let z_x = Scalar::read(reader)?;

        Ok(Self { Y_0, Y_1, Y_2, z_r, z_x })
    }

    fn size(&self) -> usize {
        RISTRETTO_COMPRESSED_SIZE * 2 + SCALAR_SIZE * 2 + self.Y_2.map_or(0, |_| RISTRETTO_COMPRESSED_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::KeyPair;
    use super::*;

    #[test]
    fn test_ciphertext_validity_proof() {
        let mut transcript = Transcript::new(b"test");
        let keypair = KeyPair::new();
        let sender = KeyPair::new();

        // Generate the commitment representing the transfer amount
        let amount = 5u64;
        let opening = PedersenOpening::generate_new();
        let commitment = PedersenCommitment::new_with_opening(amount, &opening);

        // Create the receiver handle
        let receiver_handle = keypair.get_public_key().decrypt_handle(&opening);
        // Create the sender handle
        let sender_handle = sender.get_public_key().decrypt_handle(&opening);

        // Generate the proof
        let proof = CiphertextValidityProof::new(keypair.get_public_key(), sender.get_public_key(), amount, &opening, TxVersion::V2, &mut transcript);
        assert!(proof.Y_2.is_some());

        // Generate a new transcript
        let mut transcript = Transcript::new(b"test");
        let mut batch_collector = BatchCollector::default();

        // Verify the proof
        let result = proof.pre_verify(
            &commitment,
            keypair.get_public_key(),
            sender.get_public_key(),
            &receiver_handle,
            &sender_handle,
             TxVersion::V2,
            &mut transcript,
            &mut batch_collector,
        );
        assert!(result.is_ok());
        assert!(batch_collector.verify().is_ok());
    }
}