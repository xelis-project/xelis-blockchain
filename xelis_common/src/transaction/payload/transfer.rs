use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use crate::{
    crypto::{
        elgamal::{CompressedCiphertext, CompressedCommitment, CompressedHandle, CompressedPublicKey},
        proofs::CiphertextValidityProof,
        Hash
    },
    serializer::*,
    transaction::{extra_data::UnknownExtraDataFormat, Role}
};

// TransferPayload is a public payload allowing to transfer an asset to another account
// It contains the asset hash, the destination account, the ciphertext commitment, the sender and receiver decrypt handles
// A validity proof is also provided to ensure the receiver ciphertext is valid
// to prevent any attack
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub struct TransferPayload {
    asset: Hash,
    destination: CompressedPublicKey,
    // we can put whatever we want up to EXTRA_DATA_LIMIT_SIZE bytes
    extra_data: Option<UnknownExtraDataFormat>,
    /// Represents the ciphertext along with `sender_handle` and `receiver_handle`.
    /// The opening is reused for both of the sender and receiver commitments.
    commitment: CompressedCommitment,
    sender_handle: CompressedHandle,
    receiver_handle: CompressedHandle,
    ct_validity_proof: CiphertextValidityProof,
}

impl TransferPayload {
    // Create a new transfer payload
    pub fn new(
        asset: Hash,
        destination: CompressedPublicKey,
        extra_data: Option<UnknownExtraDataFormat>,
        commitment: CompressedCommitment,
        sender_handle: CompressedHandle,
        receiver_handle: CompressedHandle,
        ct_validity_proof: CiphertextValidityProof
    ) -> Self {
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
    #[inline]
    pub fn get_destination(&self) -> &CompressedPublicKey {
        &self.destination
    }

    // Get the asset hash spent in this transfer
    #[inline]
    pub fn get_asset(&self) -> &Hash {
        &self.asset
    }

    // Get the extra data if any
    #[inline]
    pub fn get_extra_data(&self) -> &Option<UnknownExtraDataFormat> {
        &self.extra_data
    }

    // Get the ciphertext commitment
    #[inline]
    pub fn get_commitment(&self) -> &CompressedCommitment {
        &self.commitment
    }

    // Get the ciphertext decrypt handle for receiver
    #[inline]
    pub fn get_receiver_handle(&self) -> &CompressedHandle {
        &self.receiver_handle
    }

    // Get the ciphertext decrypt handle for sender
    #[inline]
    pub fn get_sender_handle(&self) -> &CompressedHandle {
        &self.sender_handle
    }

    // Get the validity proof
    #[inline]
    pub fn get_proof(&self) -> &CiphertextValidityProof {
        &self.ct_validity_proof
    }

    // Get the ciphertext based on the role in the transaction
    #[inline]
    pub fn get_ciphertext(&self, role: Role) -> CompressedCiphertext {
        let handle = match role {
            Role::Receiver => self.receiver_handle.clone(),
            Role::Sender => self.sender_handle.clone(),
        };

        CompressedCiphertext::new(self.commitment.clone(), handle)
    }

    // Take all data
    #[inline]
    pub fn consume(self) -> (Hash, CompressedPublicKey, Option<UnknownExtraDataFormat>, CompressedCommitment, CompressedHandle, CompressedHandle) {
        (self.asset, self.destination, self.extra_data, self.commitment, self.sender_handle, self.receiver_handle)
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
