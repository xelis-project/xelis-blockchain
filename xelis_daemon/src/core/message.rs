use xelis_common::{
    crypto::{
        hash::{Hash, Hashable},
        key::{PublicKey, Signature, KeyPair}
    },
    serializer::{
        Reader,
        ReaderError,
        Serializer,
        Writer
    }
};

pub const SECRET_SIZE: usize = 32;

pub trait MessageData {
    fn get_message(&self) -> &Vec<u8>;
    fn get_sender(&self) -> &PublicKey;
    fn get_receiver(&self) -> &PublicKey;
}

pub struct Message {
    hashed_secret_code: Hash,
    secret_code: [u8; SECRET_SIZE], // encrypted secret code using receiver key
    message: Vec<u8>, // encrypted message
    receiver: PublicKey,
    sender: PublicKey,
    height: u64, // build at height
    signature: Option<Signature>
}

pub struct MessageReply {
    original_hash: Hash, // hash of original message
    secret_code: [u8; SECRET_SIZE], // plain text secret code
    message: Vec<u8> // encrypted message for original sender
}

impl Message {
    pub fn new(hashed_secret_code: Hash, secret_code: [u8; SECRET_SIZE], message: Vec<u8>, receiver: PublicKey, sender: PublicKey, height: u64) -> Self {
        Self {
            hashed_secret_code,
            secret_code,
            message,
            receiver,
            sender,
            height,
            signature: None
        }
    }

    pub fn sign(&mut self, pair: &KeyPair) {
        self.signature = Some(pair.sign(self.hash().as_bytes()));
    }

    pub fn get_hashed_secret_code(&self) -> &Hash {
        &self.hashed_secret_code
    }

    pub fn get_height(&self) -> u64 {
        self.height
    }

    pub fn get_signature(&self) -> &Option<Signature> {
        &self.signature
    }
}

impl Serializer for Message {
    fn write(&self, writer: &mut Writer) {
        writer.write_hash(&self.hashed_secret_code);
        writer.write_bytes(&self.secret_code);
        writer.write_u16(&(self.message.len() as u16));
        writer.write_bytes(&self.message);
        self.receiver.write(writer);
        self.sender.write(writer);
        writer.write_u64(&self.height);
        if let Some(signature) = &self.signature {
            signature.write(writer);
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let hashed_secret_code = reader.read_hash()?;
        let secret_code = reader.read_bytes_32()?;
        let size = reader.read_u16()? as usize;
        let message: Vec<u8> = reader.read_bytes(size)?;
        let receiver = PublicKey::read(reader)?;
        let sender = PublicKey::read(reader)?;
        let height = reader.read_u64()?;
        let signature = Some(Signature::read(reader)?);

        Ok(Self {
            hashed_secret_code,
            secret_code,
            message,
            receiver,
            sender,
            height,
            signature
        })
    }
}

impl MessageData for Message {
    fn get_message(&self) -> &Vec<u8> {
        &self.message
    }

    fn get_receiver(&self) -> &PublicKey {
        &self.receiver
    }

    fn get_sender(&self) -> &PublicKey {
        &self.sender
    }
}

impl Hashable for Message {}

impl MessageReply {
    pub fn new(original_hash: Hash, secret_code: [u8; SECRET_SIZE], message: Vec<u8>) -> Self {
        Self {
            original_hash,
            secret_code,
            message
        }
    }

    pub fn get_original_hash(&self) -> &Hash {
        &self.original_hash
    }

    pub fn get_secret_code(&self) -> &[u8; SECRET_SIZE] {
        &self.secret_code
    }

    pub fn get_message(&self) -> &Vec<u8> {
        &self.message
    }
}