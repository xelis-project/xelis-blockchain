use crate::{
    crypto::{
        elgamal::{CompressedCiphertext, CompressedCommitment, CompressedHandle, CompressedPublicKey},
        proofs::{CiphertextValidityProof, CommitmentEqProof},
        Hash,
        Hashable,
        Signature,
    },
    serializer::{Reader, ReaderError, Serializer, Writer}
};
use bulletproofs::RangeProof;
use log::debug;
use serde::{Deserialize, Serialize};
use self::aead::AEADCipher;

pub mod builder;
pub mod verify;
pub mod aead;

#[cfg(test)]
mod tests;

// Maximum total size of payload across all transfers per transaction
pub const EXTRA_DATA_LIMIT_SIZE: usize = 1024;
pub const MAX_TRANSFER_COUNT: usize = 255;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Reference {
    pub hash: Hash,
    pub topoheight: u64,
}

impl PartialEq for Reference {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash && self.topoheight == other.topoheight
    }
}

pub enum Role {
    Sender,
    Receiver,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct SourceCommitment {
    commitment: CompressedCommitment,
    proof: CommitmentEqProof,
    asset: Hash,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TransferPayload {
    asset: Hash,
    destination: CompressedPublicKey,
    // we can put whatever we want up to EXTRA_DATA_LIMIT_SIZE bytes
    extra_data: Option<AEADCipher>,
    /// Represents the ciphertext along with `sender_handle` and `receiver_handle`.
    /// The opening is reused for both of the sender and receiver commitments.
    commitment: CompressedCommitment,
    sender_handle: CompressedHandle,
    receiver_handle: CompressedHandle,
    ct_validity_proof: CiphertextValidityProof,
}

// Burn is a public payload allowing to use it as a proof of burn
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BurnPayload {
    pub asset: Hash,
    pub amount: u64
}

// this enum represent all types of transaction available on XELIS Network
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TransactionType {
    Transfers(Vec<TransferPayload>),
    Burn(BurnPayload),
}

// Transaction to be sent over the network
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Transaction {
    /// Version of the transaction
    version: u8,
    // Source of the transaction
    source: CompressedPublicKey,
    /// Type of the transaction
    data: TransactionType,
    /// Fees in XELIS
    fee: u64,
    /// nonce must be equal to the one on chain account
    /// used to prevent replay attacks and have ordered transactions
    nonce: u64,
    /// We have one source commitment and equality proof per asset used in the tx.
    source_commitments: Vec<SourceCommitment>,
    /// The range proof is aggregated across all transfers and across all assets.
    range_proof: RangeProof,
    /// At which block the TX is built
    reference: Reference,
    /// The signature of the source key
    signature: Signature,
}

impl TransferPayload {
    // Create a new transfer payload
    pub fn new(asset: Hash, destination: CompressedPublicKey, extra_data: Option<AEADCipher>, commitment: CompressedCommitment, sender_handle: CompressedHandle, receiver_handle: CompressedHandle, ct_validity_proof: CiphertextValidityProof) -> Self {
        TransferPayload {
            asset,
            destination,
            extra_data,
            commitment,
            sender_handle,
            receiver_handle,
            ct_validity_proof
        }
    }

    // Get the destination key
    pub fn get_destination(&self) -> &CompressedPublicKey {
        &self.destination
    }

    // Get the asset hash spent in this transfer
    pub fn get_asset(&self) -> &Hash {
        &self.asset
    }

    // Get the extra data if any
    pub fn get_extra_data(&self) -> &Option<AEADCipher> {
        &self.extra_data
    }

    // Get the ciphertext commitment
    pub fn get_commitment(&self) -> &CompressedCommitment {
        &self.commitment
    }

    // Get the ciphertext decrypt handle for receiver
    pub fn get_receiver_handle(&self) -> &CompressedHandle {
        &self.receiver_handle
    }

    // Get the ciphertext decrypt handle for sender
    pub fn get_sender_handle(&self) -> &CompressedHandle {
        &self.sender_handle
    }

    // Get the validity proof
    pub fn get_proof(&self) -> &CiphertextValidityProof {
        &self.ct_validity_proof
    }

    pub fn get_ciphertext(&self, role: Role) -> CompressedCiphertext {
        let handle = match role {
            Role::Receiver => self.receiver_handle.clone(),
            Role::Sender => self.sender_handle.clone(),
        };

        CompressedCiphertext::new(self.commitment.clone(), handle)
    }

    // Take all data
    pub fn consume(self) -> (Hash, CompressedPublicKey, Option<AEADCipher>, CompressedCommitment, CompressedHandle, CompressedHandle) {
        (self.asset, self.destination, self.extra_data, self.commitment, self.sender_handle, self.receiver_handle)
    }
}

impl Transaction {
    pub fn new(source: CompressedPublicKey, data: TransactionType, fee: u64, nonce: u64, source_commitments: Vec<SourceCommitment>, range_proof: RangeProof, reference: Reference, signature: Signature) -> Self {
        Transaction {
            version: 0,
            source,
            data,
            fee,
            nonce,
            source_commitments,
            range_proof,
            reference,
            signature
        }
    }

    // Get the transaction version
    pub fn get_version(&self) -> u8 {
        self.version
    }

    // Get the source key
    pub fn get_source(&self) -> &CompressedPublicKey {
        &self.source
    }

    // Get the transaction type
    pub fn get_data(&self) -> &TransactionType {
        &self.data
    }

    // Get fees paid to miners
    pub fn get_fee(&self) -> u64 {
        self.fee
    }

    // Get the nonce used
    pub fn get_nonce(&self) -> u64 {
        self.nonce
    }

    // Get the source commitments
    pub fn get_source_commitments(&self) -> &Vec<SourceCommitment> {
        &self.source_commitments
    }

    // Get the range proof
    pub fn get_range_proof(&self) -> &RangeProof {
        &self.range_proof
    }

    // Get the signature of source key
    pub fn get_signature(&self) -> &Signature {
        &self.signature
    }

    // Get the block reference to determine which block the transaction is built
    pub fn get_reference(&self) -> &Reference {
        &self.reference
    }

    pub fn consume(self) -> (CompressedPublicKey, TransactionType) {
        (self.source, self.data)
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

impl Serializer for TransferPayload {
    fn write(&self, writer: &mut Writer) {
        self.asset.write(writer);
        self.destination.write(writer);
        self.extra_data.write(writer);
        self.commitment.write(writer);
        self.sender_handle.write(writer);
        self.receiver_handle.write(writer);
        self.ct_validity_proof.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<TransferPayload, ReaderError> {
        let asset = Hash::read(reader)?;
        let destination = CompressedPublicKey::read(reader)?;
        let extra_data = Option::read(reader)?;

        let commitment = CompressedCommitment::read(reader)?;
        let sender_handle = CompressedHandle::read(reader)?;
        let receiver_handle = CompressedHandle::read(reader)?;
        let ct_validity_proof = CiphertextValidityProof::read(reader)?;

        Ok(TransferPayload {
            asset,
            destination,
            extra_data,
            commitment,
            sender_handle,
            receiver_handle,
            ct_validity_proof
        })
    }

    fn size(&self) -> usize {
        self.asset.size()
        + self.destination.size()
        + self.extra_data.size()
        + self.commitment.size()
        + self.sender_handle.size()
        + self.receiver_handle.size()
        + self.ct_validity_proof.size()
    }
}

impl Serializer for BurnPayload {
    fn write(&self, writer: &mut Writer) {
        self.asset.write(writer);
        self.amount.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<BurnPayload, ReaderError> {
        let asset = Hash::read(reader)?;
        let amount = reader.read_u64()?;
        Ok(BurnPayload {
            asset,
            amount
        })
    }

    fn size(&self) -> usize {
        self.asset.size() + self.amount.size()
    }
}

impl Serializer for TransactionType {
    fn write(&self, writer: &mut Writer) {
        match self {
            TransactionType::Burn(payload) => {
                writer.write_u8(0);
                payload.write(writer);
            }
            TransactionType::Transfers(txs) => {
                writer.write_u8(1);
                // max 255 txs per transaction
                let len: u8 = txs.len() as u8;
                writer.write_u8(len);
                for tx in txs {
                    tx.write(writer);
                }
            }
        };
    }

    fn read(reader: &mut Reader) -> Result<TransactionType, ReaderError> {
        Ok(match reader.read_u8()? {
            0 => {
                let payload = BurnPayload::read(reader)?;
                TransactionType::Burn(payload)
            },
            1 => {
                let txs_count = reader.read_u8()?;
                if txs_count == 0 || txs_count > MAX_TRANSFER_COUNT as u8 {
                    return Err(ReaderError::InvalidSize)
                }

                let mut txs = Vec::with_capacity(txs_count as usize);
                for _ in 0..txs_count {
                    txs.push(TransferPayload::read(reader)?);
                }
                TransactionType::Transfers(txs)
            },
            _ => {
                return Err(ReaderError::InvalidValue)
            }
        })
    }

    fn size(&self) -> usize {
        match self {
            TransactionType::Burn(payload) => {
                1 + payload.size()
            },
            TransactionType::Transfers(txs) => {
                let mut size = 1;
                for tx in txs {
                    size += tx.size();
                }
                size
            }
        }
    }
}

impl Serializer for Transaction {
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
        self.signature.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Transaction, ReaderError> {
        let version = reader.read_u8()?;
        // At this moment we only support version 0, so we check it here directly
        if version != 0 {
            debug!("Expected version 0 got version {version}");
            return Err(ReaderError::InvalidValue)
        }

        let source = CompressedPublicKey::read(reader)?;
        let data = TransactionType::read(reader)?;
        let fee = reader.read_u64()?;
        let nonce = reader.read_u64()?;

        let commitments_len = reader.read_u8()?;
        if commitments_len == 0 || commitments_len > MAX_TRANSFER_COUNT as u8 {
            return Err(ReaderError::InvalidSize)
        }

        let mut source_commitments = Vec::with_capacity(commitments_len as usize);
        for _ in 0..commitments_len {
            source_commitments.push(SourceCommitment::read(reader)?);
        }

        let range_proof = RangeProof::read(reader)?;
        let reference = Reference::read(reader)?;
        let signature = Signature::read(reader)?;

        Ok(Transaction {
            version,
            source,
            data,
            fee,
            nonce,
            source_commitments,
            range_proof,
            reference,
            signature,
        })
    }

    fn size(&self) -> usize {
        // Version byte
        1
        + self.source.size()
        + self.data.size()
        + self.fee.size()
        + self.nonce.size()
        // Commitments length byte
        + 1
        + self.source_commitments.iter().map(|c| c.size()).sum::<usize>()
        + self.range_proof.size()
        + self.reference.size()
        + self.signature.size()
    }
}

impl Hashable for Transaction {}

impl AsRef<Transaction> for Transaction {
    fn as_ref(&self) -> &Transaction {
        self
    }
}

impl Serializer for Reference {
    fn write(&self, writer: &mut Writer) {
        self.hash.write(writer);
        writer.write_u64(&self.topoheight);
    }

    fn read(reader: &mut Reader) -> Result<Reference, ReaderError> {
        let hash = Hash::read(reader)?;
        let topoheight = reader.read_u64()?;
        Ok(Reference {
            hash,
            topoheight
        })
    }

    fn size(&self) -> usize {
        self.hash.size() + self.topoheight.size()
    }
}