use curve25519_dalek::{
    ristretto::CompressedRistretto,
    traits::{IsIdentity, MultiscalarMul, VartimeMultiscalarMul},
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
            Ciphertext,
            DecompressionError,
            PedersenCommitment,
            PedersenOpening,
            PublicKey,
            RISTRETTO_COMPRESSED_SIZE,
            SCALAR_SIZE
        },
        KeyPair,
        ProtocolTranscript
    },
    serializer::{Reader, ReaderError, Serializer, Writer},
    transaction::TxVersion
};
use super::{
    BatchCollector,
    ProofVerificationError,
    PC_GENS,
    G,
    H,
};

/// Proof that a commitment and ciphertext are equal.
#[allow(non_snake_case)]
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, JsonSchema)]
pub struct CommitmentEqProof {
    #[schemars(with = "Vec<u8>")]
    Y_0: CompressedRistretto,
    #[schemars(with = "Vec<u8>")]
    Y_1: CompressedRistretto,
    #[schemars(with = "Vec<u8>")]
    Y_2: CompressedRistretto,
    #[schemars(with = "Vec<u8>")]
    z_s: Scalar,
    #[schemars(with = "Vec<u8>")]
    z_x: Scalar,
    #[schemars(with = "Vec<u8>")]
    z_r: Scalar,
}

#[allow(non_snake_case)]
impl CommitmentEqProof {
    // warning: caller must make sure not to forget to hash the public key, ciphertext, commitment in the transcript as it is not done here
    pub fn new(
        source_keypair: &KeyPair,
        source_ciphertext: &Ciphertext,
        opening: &PedersenOpening,
        x: impl Into<Scalar>,
        tx_version: TxVersion,
        transcript: &mut Transcript,
    ) -> Self {
        transcript.equality_proof_domain_separator();

        // extract the relevant scalar and Ristretto points from the inputs
        let P_source = source_keypair.get_public_key().as_point();
        let D_source = source_ciphertext.handle().as_point();

        let s = source_keypair.get_private_key().as_scalar();
        let r = opening.as_scalar();

        // generate random masking factors that also serves as nonces
        let mut y_s = Scalar::random(&mut OsRng);
        let mut y_x = Scalar::random(&mut OsRng);
        let mut y_r = Scalar::random(&mut OsRng);

        let Y_0 = (&y_s * P_source).compress();
        let Y_1 =
            RistrettoPoint::multiscalar_mul([&y_x, &y_s], [&G, D_source]).compress();
        let Y_2 = PC_GENS.commit(y_x, y_r).compress();

        // record masking factors in the transcript
        transcript.append_point(b"Y_0", &Y_0);
        transcript.append_point(b"Y_1", &Y_1);
        transcript.append_point(b"Y_2", &Y_2);

        let c = transcript.challenge_scalar(b"c");

        // compute the masked values
        let z_s = &(&c * s) + &y_s;
        let z_x = &(&c * x.into()) + &y_x;
        let z_r = &(&c * r) + &y_r;

        if tx_version >= TxVersion::V2 {
            transcript.append_scalar(b"z_s", &z_s);
            transcript.append_scalar(b"z_x", &z_x);
            transcript.append_scalar(b"z_r", &z_r);
        }

        transcript.challenge_scalar(b"w");

        // zeroize random scalars
        y_s.zeroize();
        y_x.zeroize();
        y_r.zeroize();

        Self {
            Y_0,
            Y_1,
            Y_2,
            z_s,
            z_x,
            z_r,
        }
    }

    /// Verify that the commitment and ciphertext are equal.
    /// This function is used for batch verification.
    pub fn pre_verify(
        &self,
        source_pubkey: &PublicKey,
        source_ciphertext: &Ciphertext,
        destination_commitment: &PedersenCommitment,
        tx_version: TxVersion,
        transcript: &mut Transcript,
        batch_collector: &mut BatchCollector,
    ) -> Result<(), ProofVerificationError> {
        transcript.equality_proof_domain_separator();

        // extract the relevant scalar and Ristretto points from the inputs
        let P_source = source_pubkey.as_point();
        let C_source = source_ciphertext.commitment().as_point();
        let D_source = source_ciphertext.handle().as_point();
        let C_destination = destination_commitment.as_point();

        // include Y_0, Y_1, Y_2 to transcript and extract challenges
        transcript.validate_and_append_point(b"Y_0", &self.Y_0)?;
        transcript.validate_and_append_point(b"Y_1", &self.Y_1)?;
        transcript.validate_and_append_point(b"Y_2", &self.Y_2)?;

        let c = transcript.challenge_scalar(b"c");

        if tx_version >= TxVersion::V2 {
            transcript.append_scalar(b"z_s", &self.z_s);
            transcript.append_scalar(b"z_x", &self.z_x);
            transcript.append_scalar(b"z_r", &self.z_r);
        }

        // w used for batch verification
        let w = transcript.challenge_scalar(b"w");

        let ww = &w * &w;

        let w_negated = -&w;
        let ww_negated = -&ww;

        // check that the required algebraic condition holds
        let Y_0 = self
            .Y_0
            .decompress()
            .ok_or(DecompressionError)?;
        let Y_1 = self
            .Y_1
            .decompress()
            .ok_or(DecompressionError)?;
        let Y_2 = self
            .Y_2
            .decompress()
            .ok_or(DecompressionError)?;

        let batch_factor = Scalar::random(&mut OsRng);

        // w * z_x * G + ww * z_x * G
        batch_collector.g_scalar += (w * self.z_x + ww * self.z_x) * batch_factor;
        // -c * H + ww * z_r * H
        batch_collector.h_scalar += (-c + ww * self.z_r) * batch_factor;

        batch_collector.dynamic_scalars.extend(
            [
                self.z_s,       // z_s
                -Scalar::ONE,   // -identity
                w * self.z_s,   // w * z_s
                w_negated * c,  // -w * c
                w_negated,      // -w
                ww_negated * c, // -ww * c
                ww_negated,     // -ww
            ]
            .map(|s| s * batch_factor),
        );
        batch_collector.dynamic_points.extend([
            P_source,      // P_source
            &Y_0,          // Y_0
            D_source,      // D_source
            C_source,      // C_source
            &Y_1,          // Y_1
            C_destination, // C_destination
            &Y_2,          // Y_2
        ]);

        Ok(())
    }

    /// Verify that the commitment and ciphertext are equal.
    /// This function is used for individual verification without batch collector.
    pub fn verify(
        &self,
        source_pubkey: &PublicKey,
        ciphertext: &Ciphertext,
        commitment: &PedersenCommitment,
        transcript: &mut Transcript,
    ) -> Result<(), ProofVerificationError> {
        transcript.equality_proof_domain_separator();

        // extract the relevant scalar and Ristretto points from the inputs
        let P = source_pubkey.as_point();
        let C_ciphertext = ciphertext.commitment().as_point();
        let D = ciphertext.handle().as_point();
        let C_commitment = commitment.as_point();

        // include Y_0, Y_1, Y_2 to transcript and extract challenges
        transcript.validate_and_append_point(b"Y_0", &self.Y_0)?;
        transcript.validate_and_append_point(b"Y_1", &self.Y_1)?;
        transcript.validate_and_append_point(b"Y_2", &self.Y_2)?;

        let c = transcript.challenge_scalar(b"c");

        transcript.append_scalar(b"z_s", &self.z_s);
        transcript.append_scalar(b"z_x", &self.z_x);
        transcript.append_scalar(b"z_r", &self.z_r);

        let w = transcript.challenge_scalar(b"w");
        let ww = &w * &w;

        let w_negated = -&w;
        let ww_negated = -&ww;

        // check that the required algebraic condition holds
        let Y_0 = self
            .Y_0
            .decompress()
            .ok_or(DecompressionError)?;
        let Y_1 = self
            .Y_1
            .decompress()
            .ok_or(DecompressionError)?;
        let Y_2 = self
            .Y_2
            .decompress()
            .ok_or(DecompressionError)?;

        let check = RistrettoPoint::vartime_multiscalar_mul(
            vec![
                &self.z_s,           // z_s
                &(-&c),              // -c
                &(-&Scalar::ONE),    // -identity
                &(&w * &self.z_x),   // w * z_x
                &(&w * &self.z_s),   // w * z_s
                &(&w_negated * &c),  // -w * c
                &w_negated,          // -w
                &(&ww * &self.z_x),  // ww * z_x
                &(&ww * &self.z_r),  // ww * z_r
                &(&ww_negated * &c), // -ww * c
                &ww_negated,         // -ww
            ],
            vec![
                P,            // P
                &H,           // H
                &Y_0,         // Y_0
                &G,           // G
                D,            // D
                C_ciphertext, // C_ciphertext
                &Y_1,         // Y_1
                &G,           // G
                &H,           // H
                C_commitment, // C_commitment
                &Y_2,         // Y_2
            ],
        );

        if check.is_identity() {
            Ok(())
        } else {
            Err(ProofVerificationError::CommitmentEqProof)
        }
    }
}

#[allow(non_snake_case)]
impl Serializer for CommitmentEqProof {
    fn write(&self, writer: &mut Writer) {
        self.Y_0.write(writer);
        self.Y_1.write(writer);
        self.Y_2.write(writer);
        self.z_s.write(writer);
        self.z_x.write(writer);
        self.z_r.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let Y_0 = CompressedRistretto::read(reader)?;
        let Y_1 = CompressedRistretto::read(reader)?;
        let Y_2 = CompressedRistretto::read(reader)?;
        let z_s = Scalar::read(reader)?;
        let z_x = Scalar::read(reader)?;
        let z_r = Scalar::read(reader)?;

        Ok(Self { Y_0, Y_1, Y_2, z_s, z_x, z_r })
    }

    fn size(&self) -> usize {
        RISTRETTO_COMPRESSED_SIZE * 3 + SCALAR_SIZE * 3
    }    
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment_eq_proof() {
        let mut transcript = Transcript::new(b"test");
        let keypair = KeyPair::new();
        // Generate our initial balance
        let balance = 100u64;
        let source_balance = keypair.get_public_key().encrypt(balance);

        // Generate the ciphertext representing the TX amount
        let amount = 5;
        let ciphertext = keypair.get_public_key().encrypt(amount);

        let opening = PedersenOpening::generate_new();
        // Commitment of the final balance using the same Opening
        let commitment = PedersenCommitment::new_with_opening(balance - amount, &opening);

        // Compute the final balance
        let final_balance = source_balance - ciphertext;

        // Generate the proof
        let proof = CommitmentEqProof::new(&keypair, &final_balance, &opening, balance - amount, TxVersion::V2, &mut transcript);

        // Generate a new transcript
        let mut transcript = Transcript::new(b"test");
        let mut batch_collector = BatchCollector::default();

        // Verify the proof
        let result = proof.pre_verify(
            keypair.get_public_key(),
            &final_balance,
            &commitment,
            TxVersion::V2,
            &mut transcript,
            &mut batch_collector,
        );
        assert!(result.is_ok());
        assert!(batch_collector.verify().is_ok());
    }
}