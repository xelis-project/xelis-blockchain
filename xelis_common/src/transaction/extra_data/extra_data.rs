use crate::{
    api::DataElement,
    crypto::{
        elgamal::{CompressedHandle, PedersenOpening, PublicKey, RISTRETTO_COMPRESSED_SIZE},
        PrivateKey
    },
    serializer::*,
    transaction::Role
};
use super::{
    derive_shared_key_from_handle,
    derive_shared_key_from_opening,
    Cipher,
    CipherFormatError,
    PlaintextData,
    SharedKey,
    UnknownExtraDataFormat
};

// New version of Extra Data due to the issue of commitment randomness reuse
// https://gist.github.com/kayabaNerve/b754e9ed9fa4cc2c607f38a83aa3df2a
// We create a new opening to be independant of the amount opening.
// This is more secure and prevent bruteforce attack from the above link.
// We need to store 64 bytes more than previous version due to the exclusive handles created.
pub struct ExtraData {
    cipher: Cipher,
    sender_handle: CompressedHandle,
    receiver_handle: CompressedHandle,
}

impl ExtraData {
    // Create a new extra data that will encrypt the message for receiver & sender keys.
    // Both will be able to decrypt it.
    pub fn new(data: PlaintextData, sender: &PublicKey, receiver: &PublicKey) -> Self {
        // Generate a new opening (randomness r)
        let opening = PedersenOpening::generate_new();
        // From the randomness, derive the opening it to get the shared key
        // that will be used for encrypt/decrypt
        let k = derive_shared_key_from_opening(&opening);
        Self {
            // Encrypt the cipher using the shared key
            cipher: data.encrypt_in_place(&k),
            // Create a handle for the sender so he can decrypt the message later
            // SH = sender PK * r
            // Because SK is invert of PK, we can decrypt it by doing SH * SK 
            sender_handle: sender.decrypt_handle(&opening).compress(),
            // Same for the receiver
            // RH = receiver PK * r
            receiver_handle: receiver.decrypt_handle(&opening).compress(),
        }
    }

    // Estimate the final size for the extra data based on the plaintext format
    pub fn estimate_size(data: &DataElement) -> usize {
        let cipher: UnknownExtraDataFormat = Cipher(data.to_bytes()).into();
        // 2 bytes of additional overhead because the extra data store
        // the cipher size again 
        2 + cipher.size() + (RISTRETTO_COMPRESSED_SIZE * 2)
    }

    // Get the compressed handle based on its role
    pub fn get_handle(&self, role: Role) -> &CompressedHandle {
        match role {
            Role::Sender => &self.sender_handle,
            Role::Receiver => &self.receiver_handle,
        }
    }

    // Decrypt the message using the private key and the role to determine the correct handle to use.
    pub fn decrypt(&self, private_key: &PrivateKey, role: Role) -> Result<PlaintextData, CipherFormatError> {
        let handle = self.get_handle(role).decompress().map_err(|_| CipherFormatError)?;
        let key = derive_shared_key_from_handle(private_key, &handle);
        self.decrypt_with_shared_key(&key)
    }

    // Decrypt the message using the shared key
    pub fn decrypt_with_shared_key(&self, shared_key: &SharedKey) -> Result<PlaintextData, CipherFormatError> {
        Ok(self.cipher.clone().decrypt(shared_key)?)
    }
}

impl Serializer for ExtraData {
    fn write(&self, writer: &mut Writer) {
        self.sender_handle.write(writer); 
        self.receiver_handle.write(writer);
        self.cipher.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(Self {
            sender_handle: CompressedHandle::read(reader)?,
            receiver_handle: CompressedHandle::read(reader)?,
            cipher: Cipher::read(reader)?,
        })
    }

    fn size(&self) -> usize {
        self.cipher.size() + self.sender_handle.size() + self.receiver_handle.size()
    }
}
