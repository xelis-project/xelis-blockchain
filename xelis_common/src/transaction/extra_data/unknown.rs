use std::borrow::Cow;
use anyhow::Error;

use crate::{
    api::DataElement,
    crypto::{
        elgamal::{DecryptHandle, RISTRETTO_COMPRESSED_SIZE},
        PrivateKey
    },
    serializer::*,
    transaction::Role
};
use super::{derive_shared_key_from_handle, AEADCipherInner, ExtraData, PlaintextExtraData, SharedKey};

// A wrapper around a Vec<u8>.
// This is used for outside the wallet as we don't know what is used
// Cipher format isn't validated
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct UnknownExtraDataFormat(pub Vec<u8>);

impl UnknownExtraDataFormat {
    // Decrypt the encrypted data using the shared key
    pub fn decrypt_with_shared_key(&self, shared_key: &SharedKey) -> Result<DataElement, Error> {
        let e = ExtraData::from_bytes(&self.0)?;
        let plaintext = e.decrypt_with_shared_key(shared_key)?;
        let data = DataElement::from_bytes(&plaintext.0)?;
        Ok(data)
    }

    // Decrypt the encrypted data using the V2 version which includes the decrypt handles for each role
    pub fn decrypt_v2(&self, private_key: &PrivateKey, role: Role) -> Result<PlaintextExtraData, Error> {
        let e = ExtraData::from_bytes(&self.0)?;

        // Generate the shared key
        let handle = e.get_handle(role)
            .decompress()?;

        let shared_key = derive_shared_key_from_handle(private_key, &handle);

        let plaintext = e.decrypt_with_shared_key(&shared_key)?;
        let data = DataElement::from_bytes(&plaintext.0)?;

        Ok(PlaintextExtraData::new(
            Some(shared_key),
            data
        ))
    }

    /// WARNING: This function is deprecated and should not be used.
    /// It is kept for compatibility reasons only.
    pub fn decrypt_v1(&self, private_key: &PrivateKey, handle: &DecryptHandle) -> Result<DataElement, Error> {
        let key = derive_shared_key_from_handle(private_key, handle);
        let plaintext = AEADCipherInner(Cow::Borrowed(&self.0)).decrypt(&key)?;
        DataElement::from_bytes(&plaintext.0).map_err(|e| e.into())
    }

    /// Decrypt the encrypted data by trying to determine which version to use.
    /// V2 should always be used if possible, but for retrocompatibility reasons, V1 is also supported.
    pub fn decrypt(&self, private_key: &PrivateKey, handle: &DecryptHandle, role: Role) -> Result<PlaintextExtraData, Error> {
        // Try the new version
        // If it has 64 + 2 bytes of overhead at least, it may be a V2 
        if self.0.len() >= (RISTRETTO_COMPRESSED_SIZE * 2) + 2 {
            if let Ok(e) = self.decrypt_v2(private_key, role) {
                return Ok(e)
            }
        }

        // Otherwise, fallback on old version
        let data = self.decrypt_v1(private_key, handle)?;
        Ok(PlaintextExtraData::new(
            None,
            data
        ))
    }
}


impl Serializer for UnknownExtraDataFormat {
    fn write(&self, writer: &mut Writer) {
        self.0.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(Self(Vec::read(reader)?))
    }

    fn size(&self) -> usize {
        self.0.size()
    }
}
