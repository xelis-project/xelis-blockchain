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
    transaction::Transaction,
    serializer::{Serializer, Writer, Reader, ReaderError},
};
use super::BlockHeader;

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct Block {
    #[serde(flatten)]
    header: Arc<BlockHeader>,
    transactions: Vec<Arc<Transaction>>
}

impl Block {
    #[inline]
    pub fn new(header: impl Into<Arc<BlockHeader>>, transactions: Vec<Arc<Transaction>>) -> Self {
        Self {
            header: header.into(),
            transactions
        }
    }

    #[inline]
    pub fn to_header(self) -> Arc<BlockHeader> {
        self.header
    }

    #[inline]
    pub fn get_header(&self) -> &Arc<BlockHeader> {
        &self.header
    }

    #[inline]
    pub fn get_txs_count(&self) -> usize {
        self.transactions.len()
    }

    #[inline]
    pub fn get_transactions(&self) -> &Vec<Arc<Transaction>> {
        &self.transactions
    }

    #[inline]
    pub fn split(self) -> (Arc<BlockHeader>, Vec<Arc<Transaction>>) {
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
        let header = BlockHeader::read(reader)?;
        let mut txs = Vec::with_capacity(header.get_txs_count());
        for _ in 0..header.get_txs_count() {
            let tx = Transaction::read(reader)?;
            txs.push(Arc::new(tx));     
        }

        Ok(Block::new(header, txs))
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
        for hash in self.tips.iter() {
            tips.push(format!("{}", hash));
        }
        write!(f, "Block[height: {}, tips: [{}], timestamp: {}, nonce: {}, extra_nonce: {}, txs: {}]", self.height, tips.join(", "), self.timestamp, self.nonce, hex::encode(self.extra_nonce), self.txs_hashes.len())
    }
}