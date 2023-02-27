use xelis_common::{
    crypto::hash::{
        Hash,
        Hashable
    },
    block::CompleteBlock,
    transaction::Transaction,
    serializer::{
        Serializer,
        ReaderError,
        Reader,
        Writer
    },
};
use crate::p2p::error::P2pError;
use std::{borrow::Cow, fmt::{Display, Formatter, self}};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum ObjectRequest {
    Block(Hash),
    Transaction(Hash)
}

impl ObjectRequest {
    pub fn get_hash(&self) -> &Hash {
        match self {
            ObjectRequest::Block(hash) => hash,
            ObjectRequest::Transaction(hash) => hash
        }
    }
}

impl Serializer for ObjectRequest {
    fn write(&self, writer: &mut Writer) {
        match &self {
            ObjectRequest::Block(hash) => {
                writer.write_u8(0);
                writer.write_hash(hash);
            },
            ObjectRequest::Transaction(hash) => {
                writer.write_u8(1);
                writer.write_hash(hash);
            }
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let id = reader.read_u8()?;
        Ok(match id {
            0 => ObjectRequest::Block(reader.read_hash()?),
            1 => ObjectRequest::Transaction(reader.read_hash()?),
            _ => return Err(ReaderError::InvalidValue)
        })
    }
}

impl Display for ObjectRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Block(hash) => write!(f, "ObjectRequest[type=Block, {}]", hash),
            Self::Transaction(hash) => write!(f, "ObjectRequest[type=Transaction, {}]", hash)
        }
    }
}

pub enum OwnedObjectResponse {
    Block(CompleteBlock, Hash),
    Transaction(Transaction, Hash)
}

impl OwnedObjectResponse {
    pub fn get_hash(&self) -> &Hash {
        match self {
            OwnedObjectResponse::Block(_, hash) => hash,
            OwnedObjectResponse::Transaction(_, hash) => hash
        }
    }
}

pub enum ObjectResponse<'a> {
    Block(Cow<'a, CompleteBlock>),
    Transaction(Cow<'a, Transaction>),
    NotFound(ObjectRequest)
}

impl ObjectResponse<'_> {
    pub fn get_request(&self) -> Cow<'_, ObjectRequest> {
        match &self {
            ObjectResponse::Block(block) => Cow::Owned(ObjectRequest::Block(block.hash())),
            ObjectResponse::Transaction(tx) => Cow::Owned(ObjectRequest::Transaction(tx.hash())),
            ObjectResponse::NotFound(request) => Cow::Borrowed(request)
        }
    }

    pub fn to_owned(self) -> Result<OwnedObjectResponse, P2pError> {
        Ok(match self {
            ObjectResponse::Block(block) => {
                let block = block.into_owned();
                let hash = block.hash();
                OwnedObjectResponse::Block(block, hash)
            },
            ObjectResponse::Transaction(tx) => {
                let tx = tx.into_owned();
                let hash = tx.hash();
                OwnedObjectResponse::Transaction(tx, hash)
            },
            ObjectResponse::NotFound(request) => return Err(P2pError::ObjectNotFound(request))
        })
    }
}

impl<'a> Serializer for ObjectResponse<'a> {
    fn write(&self, writer: &mut Writer) {
        match &self {
            ObjectResponse::Block(block) => {
                writer.write_u8(0);
                block.write(writer);
            },
            ObjectResponse::Transaction(transaction) => {
                writer.write_u8(1);
                transaction.write(writer);
            },
            ObjectResponse::NotFound(obj) => {
                writer.write_u8(2);
                obj.write(writer);
            }
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let id = reader.read_u8()?;
        Ok(match id {
            0 => ObjectResponse::Block(Cow::Owned(CompleteBlock::read(reader)?)),
            1 => ObjectResponse::Transaction(Cow::Owned(Transaction::read(reader)?)),
            2 => ObjectResponse::NotFound(ObjectRequest::read(reader)?),
            _ => return Err(ReaderError::InvalidValue)
        })
    }
}
