use crate::{crypto::hash::Hash, core::{block::CompleteBlock, transaction::Transaction, serializer::Serializer, reader::{ReaderError, Reader}, writer::Writer}};
use std::borrow::Cow;
pub enum ObjectRequest {
    Block(Hash),
    Transaction(Hash)
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

pub enum ObjectResponse<'a> {
    Block(Cow<'a, CompleteBlock>),
    Transaction(Cow<'a, Transaction>)
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
            }
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let id = reader.read_u8()?;
        Ok(match id {
            0 => ObjectResponse::Block(Cow::Owned(CompleteBlock::read(reader)?)),
            1 => ObjectResponse::Transaction(Cow::Owned(Transaction::read(reader)?)),
            _ => return Err(ReaderError::InvalidValue)
        })
    }
}
