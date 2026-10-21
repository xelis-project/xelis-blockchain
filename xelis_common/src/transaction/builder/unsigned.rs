use bulletproofs::RangeProof;
use schemars::JsonSchema;
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
        Error as SerializationError,
        Readable,
        Reader,
        ReaderError,
        Serializer,
        Writable,
        Writer,
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
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
pub struct UnsignedTransaction {
    version: TxVersion,
    source: PublicKey,
    data: TransactionType,
    fee: u64,
    fee_limit: u64,
    nonce: Nonce,
    source_commitments: Vec<SourceCommitment>,
    reference: Reference,
    #[schemars(with = "Vec<u8>", description = "Binary representation of a range proof")]
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
        fee_limit: u64,
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
            fee_limit,
            nonce,
            source_commitments,
            reference,
            range_proof,
            multisig: None,
        }
    }

    // Get the source of the transaction
    pub fn source(&self) -> &PublicKey {
        &self.source
    }

    // Set a multi-signature to the transaction
    pub fn set_multisig(&mut self, multisig: MultiSig) {
        self.multisig = Some(multisig);
    }

    // Get multisig from the transaction
    pub fn multisig(&self) -> Option<&MultiSig> {
        self.multisig.as_ref()
    }

    // Get the bytes that need to be signed for the multi-signature
    fn write_no_signature<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        self.version.write(writer)?;
        self.source.write(writer)?;
        self.data.write(writer)?;
        self.fee.write(writer)?;
        if self.version >= TxVersion::V2 {
            self.fee_limit.write(writer)?;
        }
        self.nonce.write(writer)?;

        (self.source_commitments.len() as u8).write(writer)?;
        for commitment in &self.source_commitments {
            commitment.write(writer)?;
        }

        self.range_proof.write(writer)?;
        self.reference.write(writer)
    }

    // Get the hash of the transaction for the multi-signature
    // This hash must be signed by each participant of the multisig
    pub fn get_hash_for_multisig(&self) -> Result<Hash, SerializationError> {
        let mut buffer = Vec::new();
        let mut writer = Writer::new(&mut buffer);
        self.write_no_signature(&mut writer)?;
        Ok(hash(&buffer))
    }

    // Sign the transaction for the multisig
    pub fn sign_multisig(&mut self, keypair: &KeyPair, id: u8) -> Result<(), SerializationError> {
        let hash = self.get_hash_for_multisig()?;
        let multisig = self.multisig.get_or_insert_with(MultiSig::new);
        let signature = keypair.sign(hash.as_bytes());
        multisig.add_signature(SignatureId { id, signature });
        Ok(())
    }

    // Finalize the transaction by signing it
    pub fn finalize(self, keypair: &KeyPair) -> Result<Transaction, SerializationError> {
        let bytes = self.to_bytes()?;
        let signature = keypair.sign(&bytes);

        Ok(Transaction::new(
            self.version,
            self.source,
            self.data,
            self.fee,
            self.fee_limit,
            self.nonce,
            self.source_commitments,
            self.range_proof,
            self.reference,
            self.multisig,
            signature,
        ))
    }
}

impl Serializer for UnsignedTransaction {
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            self.write_no_signature(writer)?;
            if self.version > TxVersion::V0 {
                self.multisig.write(writer)?;
            }
            Ok(())
        })
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            let version = TxVersion::read(reader)?;
            let source = PublicKey::read(reader)?;
            let data = TransactionType::read(reader)?;
            let fee = u64::read(reader)?;
            let fee_limit = if version >= TxVersion::V2 {
                u64::read(reader)?
            } else {
                fee
            };

            let nonce = Nonce::read(reader)?;

            let source_commitments_len = u8::read(reader)?;
            let mut source_commitments = Vec::with_capacity(source_commitments_len as usize);
            for _ in 0..source_commitments_len {
                source_commitments.push(SourceCommitment::read(reader)?);
            }

            let range_proof = RangeProof::read(reader)?;
            let reference = Reference::read(reader)?;

            let multisig = if version > TxVersion::V0 {
                Option::read(reader)?
            } else {
                None
            };

            Ok(Self {
                version,
                source,
                data,
                fee,
                fee_limit,
                nonce,
                source_commitments,
                reference,
                range_proof,
                multisig,
            })
        })
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

        if self.version >= TxVersion::V2 {
            size += self.fee_limit.size();
        }

        size
    }
}