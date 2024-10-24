use anyhow::Error;

use crate::{
    config::PREFIX_PROOF,
    serializer::{
        Reader,
        ReaderError,
        Serializer,
        Writer
    }
};
use super::{
    bech32::{convert_bits, encode, decode, Bech32Error},
    proofs::BalanceProof
};

/// A human reable proof that can be shared with other parties as a message.
pub enum HumanReadableProof {
    Balance {
        proof: BalanceProof,
        topoheight: u64
    }
}

impl HumanReadableProof {
    // Transform a shareable proof to a human readable string
    pub fn as_string(&self) -> Result<String, Bech32Error> {
        let bits = convert_bits(&self.to_bytes(), 8, 5, true)?;
        let result = encode(PREFIX_PROOF.to_owned(), &bits)?;

        Ok(result)
    }

    // Transform a human readable string to a shareable proof
    pub fn from_string(proof: &str) -> Result<Self, Error> {
        let (hrp, decoded) = decode(proof)?;
        if hrp != PREFIX_PROOF {
            return Err(Bech32Error::InvalidPrefix(hrp, PREFIX_PROOF.to_owned()).into())
        }

        let bits = convert_bits(&decoded, 5, 8, false)?;
        let proof = HumanReadableProof::from_bytes(&bits)?;

        Ok(proof)
    }
}

impl Serializer for HumanReadableProof {
    fn write(&self, writer: &mut Writer) {
        match self {
            HumanReadableProof::Balance { proof, topoheight } => {
                writer.write_u8(0);
                proof.write(writer);
                topoheight.write(writer);
            }
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let proof = match reader.read_u8()? {
            0 => {
                let proof = BalanceProof::read(reader)?;
                let topoheight = u64::read(reader)?;
        
                HumanReadableProof::Balance { proof, topoheight }
            },
            _ => return Err(ReaderError::InvalidValue)
        };

        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use merlin::Transcript;

    use crate::crypto::{proofs::BatchCollector, KeyPair};
    use super::*;

    #[test]
    fn test_hr_balance_proof() {
        let keypair = KeyPair::new();
        // Generate the balance
        let amount = 100u64;
        let ct = keypair.get_public_key().encrypt(amount);

        // Create proof
        let mut transcript = Transcript::new(b"test");
        let proof = BalanceProof::prove(&keypair, amount, ct.clone(), &mut transcript);
        let shareable = HumanReadableProof::Balance { proof, topoheight: 0 };

        // Transform to string and back to a shareable proof
        let string = shareable.as_string().unwrap();
        assert!(string.starts_with(PREFIX_PROOF));

        let HumanReadableProof::Balance { proof, topoheight } = HumanReadableProof::from_string(&string).unwrap();
        assert_eq!(topoheight, 0);

        // Verify it
        let mut transcript = Transcript::new(b"test");
        let mut batch_collector = BatchCollector::default();
        assert!(proof.verify(keypair.get_public_key(), ct, &mut transcript, &mut batch_collector).is_ok());
        assert!(batch_collector.verify().is_ok());
    }
}