use bulletproofs::RangeProof;
use serde::{Deserialize, Serialize};

use crate::{
    account::Nonce,
    crypto::{
        hash,
        Hash,
        KeyPair,
        PublicKey
    },
    serializer::{
        Reader,
        ReaderError,
        Serializer,
        Writer
    },
    transaction::{
        multisig::{MultiSig, SignatureId},
        Reference,
        SourceCommitment,
        Transaction,
        TransactionType,
        TxVersion
    }
};

// Used to build the final transaction
// It can include the multi-signature logic
// by signing it
#[derive(Clone, Serialize, Deserialize)]
pub struct UnsignedTransaction {
    version: TxVersion,
    source: PublicKey,
    data: TransactionType,
    fee: u64,
    nonce: Nonce,
    source_commitments: Vec<SourceCommitment>,
    reference: Reference,
    range_proof: RangeProof,
    multisig: Option<MultiSig>,
}

impl UnsignedTransaction {
    // Create a new unsigned transaction
    pub fn new(
        version: TxVersion,
        source: PublicKey,
        data: TransactionType,
        fee: u64,
        nonce: Nonce,
        source_commitments: Vec<SourceCommitment>,
        reference: Reference,
        range_proof: RangeProof,
    ) -> Self {
        Self {
            version,
            source,
            data,
            fee,
            nonce,
            source_commitments,
            reference,
            range_proof,
            multisig: None,
        }
    }

    // Set a multi-signature to the transaction
    pub fn set_multisig(&mut self, multisig: MultiSig) {
        self.multisig = Some(multisig);
    }

    // Get the bytes that need to be signed for the multi-signature
    fn write_no_signature(&self, writer: &mut Writer) {
        self.version.write(writer);
        self.source.write(writer);
        self.data.write(writer);
        self.fee.write(writer);
        self.nonce.write(writer);

        writer.write_u8(self.source_commitments.len() as u8);
        for commitment in &self.source_commitments {
            commitment.write(writer);
        }

        self.range_proof.write(writer);
        self.reference.write(writer);
    }

    // Get the hash of the transaction for the multi-signature
    // This hash must be signed by each participant of the multisig
    pub fn get_hash_for_multisig(&self) -> Hash {
        let mut writer = Writer::new();
        self.write_no_signature(&mut writer);
        hash(writer.as_bytes())
    }

    // Sign the transaction for the multisig
    pub fn sign_multisig(&mut self, keypair: &KeyPair, id: u8) {
        let hash = self.get_hash_for_multisig();
        let multisig = self.multisig.get_or_insert_with(MultiSig::new);
        let signature = keypair.sign(hash.as_bytes());
        multisig.add_signature(SignatureId { id, signature });
    }

    // Finalize the transaction by signing it
    pub fn finalize(self, keypair: &KeyPair) -> Transaction {
        let bytes = self.to_bytes();
        let signature = keypair.sign(&bytes);

        Transaction::new(
            self.version,
            self.source,
            self.data,
            self.fee,
            self.nonce,
            self.source_commitments,
            self.range_proof,
            self.reference,
            self.multisig,
            signature,
        )
    }
}

impl Serializer for UnsignedTransaction {
    fn write(&self, writer: &mut Writer) {
        self.write_no_signature(writer);
        if self.version != TxVersion::V0 {
            self.multisig.write(writer);
        }
    }

    // Should never be called
    fn read(_: &mut Reader) -> Result<Self, ReaderError> {
        Err(ReaderError::InvalidValue)
    }

    fn size(&self) -> usize {
        let mut size = self.version.size()
            + self.source.size()
            + self.data.size()
            + self.fee.size()
            + self.nonce.size()
            + 1; // source_commitments length

        for commitment in &self.source_commitments {
            size += commitment.size();
        }

        size += self.range_proof.size()
            + self.reference.size();

        if self.version != TxVersion::V0 {
            size += self.multisig.size();
        }

        size
    }
}