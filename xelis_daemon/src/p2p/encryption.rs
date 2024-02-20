use thiserror::Error;

// Two packets are created: Rekey and RekeyAck
// Rekey is sent by the peer to rekey the connection
// RekeyAck is sent by the peer to acknowledge the rekey
pub enum Encryption {
    // This is the temporary asymetric key to decrypt data on handshake response
    // This is our private key, we share the public key to the peer
    Exchange(Vec<u8>),
    // It got selected by the peer and we need to use it to encrypt/decrypt data
    // Only the outgoing peer can select the key and rekey it.
    Ready {
        // This is the symetric key used to encrypt the data
        key: Vec<u8>,
        // Nonce to use for the next outgoing packet
        nonce_out: u64,
        // Nonce to expect for the next incoming packet
        nonce_in: u64
    },
    // During a key rotation, we need to keep the old key and the new key
    // We encrypt everything with the new key
    // and decrypt everything with the old key until the peer acknowledge the rekey
    KeyRotation {
        old_key: Vec<u8>,
        new_key: Vec<u8>,
        new_nonce_out: u64,
        old_nonce_in: u64,
    }
}

#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("Encryption is not ready")]
    NotReady
}

impl Encryption {
    pub fn new() -> Self {
        // TODO
        Encryption::Exchange(Vec::new())
    }

    pub fn encrypt_packet(&mut self, input: &[u8], buffer: &mut [u8]) -> Result<(), EncryptionError> {
        match self {
            Encryption::Ready { key, nonce_out, .. } => {
                // Increment the nonce so we don't use the same nonce twice
                *nonce_out += 1;

                // Encrypt the packet
            },
            Encryption::KeyRotation { new_key, new_nonce_out, .. } => {
                // Increment the nonce so we don't use the same nonce twice
                *new_nonce_out += 1;

                // Encrypt the packet
            },
            _ => return Err(EncryptionError::NotReady),
        };
        Ok(())
    }

    // Decrypt a packet using the shared symetric key
    pub fn decrypt_packet(&self, input: &mut [u8]) -> Result<(), EncryptionError> {
        match self {
            Encryption::Ready { key, nonce_in, .. } => {
                // Decrypt packet
                Ok(())
            },
            _ => Err(EncryptionError::NotReady),
        }
    }

    // Rotate the key with a new one. This expect that we send a Rekey packet to the peer
    pub fn rotate_key(&mut self, new_key: Vec<u8>) -> Result<(), EncryptionError> {
        match self {
            Encryption::Ready { key, nonce_out: _, nonce_in } => {
                *self = Encryption::KeyRotation {
                    old_key: key.clone(),
                    new_key,
                    new_nonce_out: 0,
                    old_nonce_in: *nonce_in
                };
                Ok(())
            },
            _ => Err(EncryptionError::NotReady),
        }
    }

    // Confirm that the peer acknowledge the key rotation
    pub fn confirm_rotate(&mut self) -> Result<(), EncryptionError> {
        match self {
            Encryption::KeyRotation { old_key: _, new_key, new_nonce_out, old_nonce_in: _ } => {
                *self = Encryption::Ready {
                    key: new_key.clone(),
                    nonce_out: *new_nonce_out,
                    nonce_in: 0
                };
                Ok(())
            },
            _ => Err(EncryptionError::NotReady),
        }
    }

    // Update the key with a new one. This is used when we receive a Rekey packet from the peer
    pub fn update_key(&mut self, new_key: Vec<u8>) -> Result<(), EncryptionError> {
        match self {
            Encryption::Exchange(_) => {
                *self = Encryption::Ready {
                    key: new_key,
                    nonce_out: 0,
                    nonce_in: 0
                };
                Ok(())
            },
            Encryption::Ready { key, nonce_out, nonce_in } => {
                *key = new_key;
                *nonce_out = 0;
                *nonce_in = 0;
                Ok(())
            },
            _ => Err(EncryptionError::NotReady),
        }
    }
}