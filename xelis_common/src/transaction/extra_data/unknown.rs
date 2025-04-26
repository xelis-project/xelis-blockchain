use std::borrow::Cow;
use anyhow::Error;

use crate::{
    api::DataElement,
    crypto::{
        elgamal::DecryptHandle,
        PrivateKey
    },
    serializer::*,
    transaction::Role
};
use super::{
    derive_shared_key_from_handle,
    plaintext::PlaintextFlag,
    AEADCipher,
    AEADCipherInner,
    Cipher,
    ExtraData,
    ExtraDataType,
    PlaintextExtraData,
    SharedKey
};

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

    // Decrypt from the versioned extra data format
    fn decrypt_typed(&self, private_key: &PrivateKey, role: Role) -> Result<PlaintextExtraData, Error> {
        let typed = ExtraDataType::from_bytes(&self.0)?;
        match typed {
            ExtraDataType::Private(payload) => self.decrypt_extra_data(&payload, private_key, role),
            ExtraDataType::Public(payload) => {
                let decoded = DataElement::from_bytes(&payload.0)?;
                Ok(PlaintextExtraData::new(None, Some(decoded), PlaintextFlag::Public))
            }
            ExtraDataType::Proprietary(payload) => Ok(PlaintextExtraData::new(
                None,
                Some(DataElement::Value(payload.into())),
                PlaintextFlag::Proprietary
            )),
        }
    }

    // Decrypt the extra data by generating the shared key for decryption and decode its result into a data element 
    fn decrypt_extra_data(&self, extra_data: &ExtraData, private_key: &PrivateKey, role: Role) -> Result<PlaintextExtraData, Error> {
        // Generate the shared key
        let handle = extra_data.get_handle(role)
            .decompress()?;

        let shared_key = derive_shared_key_from_handle(private_key, &handle);

        let plaintext = extra_data.decrypt_with_shared_key(&shared_key)?;
        let data = DataElement::from_bytes(&plaintext.0)?;

        Ok(PlaintextExtraData::new(
            Some(shared_key),
            Some(data),
            PlaintextFlag::Private
        ))
    }

    // Decrypt the encrypted data using the V2 version which includes the decrypt handles for each role
    fn decrypt_v2(&self, private_key: &PrivateKey, role: Role) -> Result<PlaintextExtraData, Error> {
        let e = ExtraData::from_bytes(&self.0)?;
        self.decrypt_extra_data(&e, private_key, role)
    }

    /// WARNING: This function is deprecated and should not be used.
    /// It is kept for compatibility reasons only.
    fn decrypt_v1(&self, private_key: &PrivateKey, handle: &DecryptHandle) -> Result<DataElement, Error> {
        let key = derive_shared_key_from_handle(private_key, handle);
        let plaintext = AEADCipherInner(Cow::Borrowed(&self.0)).decrypt(&key)?;
        DataElement::from_bytes(&plaintext.0).map_err(|e| e.into())
    }

    /// Decrypt the encrypted data by trying to determine which version to use.
    /// V2 should always be used if possible, but for retrocompatibility reasons, V1 is also supported.
    pub fn decrypt(&self, private_key: &PrivateKey, handle: Option<&DecryptHandle>, role: Role) -> Result<PlaintextExtraData, Error> {
        // Try to decrypt our new version supporting different formats
        let mut res = self.decrypt_typed(private_key, role);

        // Try the v2 if we had an error
        if res.is_err() {
            res = self.decrypt_v2(private_key, role);
        }

        // If we got an error during previous decoding
        // fallback on old version if the handle is provided
        if let Some(handle) = handle.filter(|_| res.is_err()) {
            let data = self.decrypt_v1(private_key, handle)?;
            res = Ok(PlaintextExtraData::new(
                None,
                Some(data),
                PlaintextFlag::Private
            ));
        }

        res
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

impl From<AEADCipher> for UnknownExtraDataFormat {
    fn from(value: AEADCipher) -> Self {
        Self(value.0)
    }
}

impl From<Cipher> for UnknownExtraDataFormat {
    fn from(value: Cipher) -> Self {
        Self(value.0)
    }
}

impl From<ExtraData> for UnknownExtraDataFormat {
    fn from(value: ExtraData) -> Self {
        Self(value.to_bytes())
    }
}

impl From<ExtraDataType> for UnknownExtraDataFormat {
    fn from(value: ExtraDataType) -> Self {
        Self(value.to_bytes())
    }
}