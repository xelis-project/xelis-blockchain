use xelis_common::{
    block::{
        Block,
        BlockHeader
    },
    crypto::{
        Hash,
        Hashable,
        HASH_SIZE
    },
    immutable::Immutable,
    serializer::{
        Reader,
        ReaderError,
        Serializer,
        Writer
    },
    transaction::Transaction
};
use std::{borrow::Cow, fmt::{Display, Formatter, self}};

use crate::p2p::error::P2pError;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum ObjectRequest {
    Block(Immutable<Hash>),
    BlockHeader(Immutable<Hash>),
    Transaction(Immutable<Hash>)
}

impl ObjectRequest {
    pub fn get_hash(&self) -> &Hash {
        match self {
            Self::Block(hash) => hash,
            Self::BlockHeader(hash) => hash,
            Self::Transaction(hash) => hash
        }
    }
}

impl Serializer for ObjectRequest {
    fn write(&self, writer: &mut Writer) {
        match &self {
            Self::Block(hash) => {
                writer.write_u8(0);
                writer.write_hash(hash);
            },
            Self::BlockHeader(hash) => {
                writer.write_u8(1);
                writer.write_hash(hash);
            },
            Self::Transaction(hash) => {
                writer.write_u8(2);
                writer.write_hash(hash);
            }
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let id = reader.read_u8()?;
        Ok(match id {
            0 => ObjectRequest::Block(Immutable::read(reader)?),
            1 => ObjectRequest::BlockHeader(Immutable::read(reader)?),
            2 => ObjectRequest::Transaction(Immutable::read(reader)?),
            _ => return Err(ReaderError::InvalidValue)
        })
    }

    fn size(&self) -> usize {
        1 + HASH_SIZE
    }
}

impl Display for ObjectRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Block(hash) => write!(f, "ObjectRequest[type=Block, {}]", hash),
            Self::BlockHeader(hash) => write!(f, "ObjectRequest[type=BlockHeader, {}]", hash),
            Self::Transaction(hash) => write!(f, "ObjectRequest[type=Transaction, {}]", hash)
        }
    }
}

#[derive(Debug, Clone)]
pub enum OwnedObjectResponse {
    Block(Block, Hash),
    BlockHeader(BlockHeader, Hash),
    Transaction(Transaction, Hash),
    NotFound(ObjectRequest)
}

impl OwnedObjectResponse {
    pub fn get_hash(&self) -> &Hash {
        match self {
            Self::Block(_, hash) => hash,
            Self::BlockHeader(_, hash) => hash,
            Self::Transaction(_, hash) => hash,
            Self::NotFound(request) => request.get_hash(),
        }
    }

    pub fn get_request(&self) -> ObjectRequest {
        match &self {
            Self::Block(_, hash) => ObjectRequest::Block(Immutable::Owned(hash.clone())),
            Self::BlockHeader(_, hash) => ObjectRequest::BlockHeader(Immutable::Owned(hash.clone())),
            Self::Transaction(_, hash) => ObjectRequest::Transaction(Immutable::Owned(hash.clone())),
            Self::NotFound(request) => request.clone(),
        }
    }

    pub fn into_transaction(self) -> Result<(Transaction, Hash), P2pError> {
        match self {
            Self::Transaction(tx, hash) => Ok((tx, hash)),
            response => Err(P2pError::ExpectedTransaction(response)),
        }
    }

    pub fn into_block_header(self) -> Result<(BlockHeader, Hash), P2pError> {
        match self {
            Self::BlockHeader(block, hash) => Ok((block, hash)),
            response => Err(P2pError::ExpectedBlockHeader(response)),
        }
    }

    pub fn into_block(self) -> Result<(Block, Hash), P2pError> {
        match self {
            Self::Block(block, hash) => Ok((block, hash)),
            response => Err(P2pError::ExpectedBlock(response)),
        }
    }
}

#[derive(Debug)]
pub enum ObjectResponse<'a> {
    Block(Cow<'a, Block>),
    BlockHeader(Cow<'a, BlockHeader>),
    Transaction(Cow<'a, Transaction>),
    NotFound(ObjectRequest)
}

impl ObjectResponse<'_> {
    pub fn get_request(&self) -> Cow<'_, ObjectRequest> {
        match &self {
            Self::Block(block) => Cow::Owned(ObjectRequest::Block(Immutable::Owned(block.hash()))),
            Self::BlockHeader(header) => Cow::Owned(ObjectRequest::BlockHeader(Immutable::Owned(header.hash()))),
            Self::Transaction(tx) => Cow::Owned(ObjectRequest::Transaction(Immutable::Owned(tx.hash()))),
            Self::NotFound(request) => Cow::Borrowed(request)
        }
    }

    // Be careful, this method ensure that the hash is the correct
    // one for each object
    pub fn to_owned(self) -> OwnedObjectResponse {
        match self {
            Self::Block(block) => {
                let block = block.into_owned();
                let hash = block.hash();
                OwnedObjectResponse::Block(block, hash)
            },
            Self::BlockHeader(header) => {
                let hash = header.hash();
                OwnedObjectResponse::BlockHeader(header.into_owned(), hash)
            },
            Self::Transaction(tx) => {
                let tx = tx.into_owned();
                let hash = tx.hash();
                OwnedObjectResponse::Transaction(tx, hash)
            },
            ObjectResponse::NotFound(request) => OwnedObjectResponse::NotFound(request)
        }
    }
}

impl<'a> Serializer for ObjectResponse<'a> {
    fn write(&self, writer: &mut Writer) {
        match &self {
            Self::Block(block) => {
                writer.write_u8(0);
                block.write(writer);
            },
            Self::BlockHeader(header) => {
                writer.write_u8(1);
                header.write(writer);
            }
            Self::Transaction(transaction) => {
                writer.write_u8(2);
                transaction.write(writer);
            },
            Self::NotFound(obj) => {
                writer.write_u8(3);
                obj.write(writer);
            }
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let id = reader.read_u8()?;
        Ok(match id {
            0 => Self::Block(Cow::Owned(Block::read(reader)?)),
            1 => Self::BlockHeader(Cow::Owned(BlockHeader::read(reader)?)),
            2 => Self::Transaction(Cow::Owned(Transaction::read(reader)?)),
            3 => Self::NotFound(ObjectRequest::read(reader)?),
            _ => return Err(ReaderError::InvalidValue)
        })
    }

    fn size(&self) -> usize {
        1 + match &self {
            Self::Block(block) => block.size(),
            Self::BlockHeader(header) => header.size(),
            Self::Transaction(transaction) => transaction.size(),
            Self::NotFound(obj) => obj.size()
        }
    }
}

impl Display for OwnedObjectResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Block(block, hash) => write!(f, "OwnedObjectResponse({}, {})", block, hash),
            Self::BlockHeader(block, hash) => write!(f, "OwnedObjectResponse({}, {})", block, hash),
            Self::Transaction(_, hash) => write!(f, "OwnedObjectResponse(Transaction({}))", hash),
            Self::NotFound(request) => write!(f, "OwnedObjectResponse(NotFound({}))", request),
        }
    }
}