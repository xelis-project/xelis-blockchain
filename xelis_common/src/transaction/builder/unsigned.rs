use bulletproofs::RangeProof;

use crate::{
    crypto::{
        PublicKey,
        KeyPair
    },
    serializer::{
        Reader,
        ReaderError,
        Serializer,
        Writer
    },
    transaction::{
        multisig::MultiSig,
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
pub struct UnsignedTransaction {
    version: TxVersion,
    source: PublicKey,
    data: TransactionType,
    fee: u64,
    nonce: u64,
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
        nonce: u64,
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

    // Should never be called
    fn read(_: &mut Reader) -> Result<Self, ReaderError> {
        Err(ReaderError::InvalidValue)
    }
}