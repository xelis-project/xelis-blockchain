use std::{
    fmt::{Display, Formatter},
    fmt::Error,
    ops::Deref,
    sync::Arc
};
use crate::{
    crypto::{
        Hashable,
        Hash,
    },
    immutable::Immutable,
    transaction::Transaction,
    serializer::{Serializer, Writer, Reader, ReaderError},
};
use super::BlockHeader;

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct Block {
    #[serde(flatten)]
    header: Immutable<BlockHeader>,
    transactions: Vec<Immutable<Transaction>>
}

impl Block {
    pub fn new(block: Immutable<BlockHeader>, transactions: Vec<Immutable<Transaction>>) -> Self {
        Block {
            header: block,
            transactions
        }
    }

    pub fn with(mut block: BlockHeader, transactions: Vec<Transaction>) -> Self {
        transactions.iter().for_each(|tx| {
            block.txs_hashes.insert(tx.hash());
        });

        Block {
            header: Immutable::Owned(block),
            transactions: transactions.into_iter().map(|tx| Immutable::Owned(tx)).collect()
        }
    }

    pub fn to_header(self) -> Arc<BlockHeader> {
        self.header.to_arc()
    }

    pub fn get_header(&self) -> &BlockHeader {
        &self.header
    }

    pub fn get_txs_count(&self) -> usize {
        self.transactions.len()
    }

    pub fn get_transactions(&self) -> &Vec<Immutable<Transaction>> {
        &self.transactions
    }

    pub fn split(self) -> (Immutable<BlockHeader>, Vec<Immutable<Transaction>>) {
        (self.header, self.transactions)
    }
}

impl Serializer for Block {
    fn write(&self, writer: &mut Writer) {
        self.header.write(writer);
        for tx in &self.transactions {
            tx.write(writer);
        }
    }

    fn read(reader: &mut Reader) -> Result<Block, ReaderError> {
        let block = BlockHeader::read(reader)?;
        let mut txs: Vec<Immutable<Transaction>> = Vec::new();
        for _ in 0..block.get_txs_count() {
            let tx = Transaction::read(reader)?;
            txs.push(Immutable::Owned(tx));     
        }

        Ok(Block::new(Immutable::Owned(block), txs))
    }

    fn size(&self) -> usize {
        self.header.size() + self.transactions.iter().map(|tx| tx.size()).sum::<usize>()
    }
}

impl Hashable for Block {
    fn hash(&self) -> Hash {
        self.header.hash()
    }
}

impl Deref for Block {
    type Target = BlockHeader;

    fn deref(&self) -> &Self::Target {
        &self.get_header()        
    }
}

impl Display for Block {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        let mut tips = Vec::with_capacity(self.tips.len());
        for hash in &self.tips {
            tips.push(format!("{}", hash));
        }
        write!(f, "Block[height: {}, tips: [{}], timestamp: {}, nonce: {}, extra_nonce: {}, txs: {}]", self.height, tips.join(", "), self.timestamp, self.nonce, hex::encode(self.extra_nonce), self.txs_hashes.len())
    }
}