use std::fmt::{self, Display, Formatter};
use anyhow::Error;
use serde::de::Error as SerdeError;

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
    bech32::{
        convert_bits,
        decode,
        encode,
        Bech32Error
    },
    proofs::{BalanceProof, OwnershipProof},
    Hash
};

/// A human reable proof that can be shared with other parties as a message.
pub enum HumanReadableProof {
    /// Prove the whole asset balance of an account.
    Balance {
        /// The balance proof.
        proof: BalanceProof,
        /// The asset of the proof.
        asset: Hash,
        /// The topological height of the balance ciphertext.
        topoheight: u64
    },
    /// Ownership proofs are used to prove that the prover owns a certain amount of an asset.
    Ownership {
        /// The ownership proof.
        proof: OwnershipProof,
        /// The asset of the proof.
        asset: Hash,
        /// The topological height of the balance ciphertext.
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
            HumanReadableProof::Balance { proof, asset, topoheight } => {
                writer.write_u8(0);
                proof.write(writer);
                asset.write(writer);
                topoheight.write(writer);
            },
            HumanReadableProof::Ownership { proof, asset, topoheight } => {
                writer.write_u8(1);
                proof.write(writer);
                asset.write(writer);
                topoheight.write(writer);
            }
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let proof = match reader.read_u8()? {
            0 => {
                let proof = BalanceProof::read(reader)?;
                let asset = Hash::read(reader)?;
                let topoheight = u64::read(reader)?;
        
                HumanReadableProof::Balance { proof, asset, topoheight }
            },
            1 => {
                let proof = OwnershipProof::read(reader)?;
                let asset = Hash::read(reader)?;
                let topoheight = u64::read(reader)?;
        
                HumanReadableProof::Ownership { proof, asset, topoheight }
            },
            _ => return Err(ReaderError::InvalidValue)
        };

        Ok(proof)
    }

    fn size(&self) -> usize {
        let mut size = 1;
        match self {
            HumanReadableProof::Balance { proof, asset, topoheight } => {
                size += proof.size() + asset.size() + topoheight.size();
            },
            HumanReadableProof::Ownership { proof, asset, topoheight } => {
                size += proof.size() + asset.size() + topoheight.size();
            }
        }

        size
    }
}

impl serde::Serialize for HumanReadableProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'a> serde::Deserialize<'a> for HumanReadableProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a>
    {
        let s = String::deserialize(deserializer)?;
        HumanReadableProof::from_string(&s).map_err(SerdeError::custom)
    }
}

impl Display for HumanReadableProof {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_string().map_err(|_| fmt::Error)?)
    }
}

#[cfg(test)]
mod tests {
    use merlin::Transcript;

    use crate::{
        config::XELIS_ASSET,
        crypto::{
            proofs::BatchCollector,
            KeyPair
        }
    };
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
        let shareable = HumanReadableProof::Balance { proof, asset: XELIS_ASSET, topoheight: 0 };

        // Transform to string and back to a shareable proof
        let string = shareable.as_string().unwrap();
        assert!(string.starts_with(PREFIX_PROOF));

        let HumanReadableProof::Balance { proof, asset, topoheight } = HumanReadableProof::from_string(&string).unwrap() else {
            panic!("Failed to parse the shareable proof");
        };
        assert_eq!(topoheight, 0);
        assert_eq!(asset, XELIS_ASSET);

        // Verify it
        let mut transcript = Transcript::new(b"test");
        let mut batch_collector = BatchCollector::default();
        assert!(proof.pre_verify(keypair.get_public_key(), ct, &mut transcript, &mut batch_collector).is_ok());
        assert!(batch_collector.verify().is_ok());
    }

    #[test]
    fn test_hr_ownership_proof() {
        let keypair = KeyPair::new();
        // Generate the balance
        let balance = 100u64;
        let amount = 10u64;
        let ct = keypair.get_public_key().encrypt(balance);

        // Create proof
        let mut transcript = Transcript::new(b"test");
        let proof = OwnershipProof::prove(&keypair, balance, amount, ct.clone(), &mut transcript).unwrap();
        let shareable = HumanReadableProof::Ownership { proof, asset: XELIS_ASSET, topoheight: 0 };

        // Transform to string and back to a shareable proof
        let string = shareable.as_string().unwrap();
        assert!(string.starts_with(PREFIX_PROOF));

        let HumanReadableProof::Ownership { proof, asset, topoheight } = HumanReadableProof::from_string(&string).unwrap() else {
            panic!("Failed to parse the shareable proof");
        };
        assert_eq!(topoheight, 0);
        assert_eq!(asset, XELIS_ASSET);

        // Verify it
        let mut transcript = Transcript::new(b"test");
        let mut batch_collector = BatchCollector::default();
        assert!(proof.pre_verify(keypair.get_public_key(), ct, &mut transcript, &mut batch_collector).is_ok());
        assert!(batch_collector.verify().is_ok());
    }
}