use async_trait::async_trait;
use log::trace;
use xelis_common::{
    block::{Block, BlockHeader, TopoHeight},
    crypto::Hash,
    immutable::Immutable
};

use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::Column,
        sled::{TOP_HEIGHT, TOP_TOPO_HEIGHT},
        DagOrderProvider,
        DifficultyProvider,
        RocksStorage,
        StateProvider,
        TransactionProvider
    }
};

#[async_trait]
impl StateProvider for RocksStorage {
    // Get the top block hash of the chain
    async fn get_top_block_hash(&self) -> Result<Hash, BlockchainError> {
        trace!("get top block hash");
        self.get_hash_at_topo_height(self.get_top_topoheight().await?).await
    }

    // Get the top block of the chain, based on top block hash
    async fn get_top_block(&self) -> Result<Block, BlockchainError> {
        trace!("get top block");
        let (header, _) = self.get_top_block_header().await?;
        let mut transactions = Vec::with_capacity(header.get_txs_count());
        for tx in header.get_transactions() {
            let transaction = self.get_transaction(tx).await?;
            transactions.push(transaction);
        }

        let block = Block::new(header, transactions);
        Ok(block)
    }

    // Get the top block header of the chain, based on top block hash
    async fn get_top_block_header(&self) -> Result<(Immutable<BlockHeader>, Hash), BlockchainError> {
        trace!("get top block header");
        let hash = self.get_top_block_hash().await?;
        Ok((self.get_block_header_by_hash(&hash).await?, hash))
    }

    // Get the top topoheight of the chain
    async fn get_top_topoheight(&self) -> Result<TopoHeight, BlockchainError> {
        trace!("get top topoheight");
        self.load_optional_from_disk(Column::Common, TOP_TOPO_HEIGHT)
            .map(|v| v.unwrap_or(0))
    }

    // Set the top topoheight of the chain
    async fn set_top_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("set new top topoheight at {}", topoheight);
        self.insert_into_disk(Column::Common, TOP_TOPO_HEIGHT, &topoheight.to_be_bytes())
    }

    // Get the top height of the chain
    async fn get_top_height(&self) -> Result<u64, BlockchainError> {
        trace!("get top height");
        self.load_optional_from_disk(Column::Common, TOP_HEIGHT)
            .map(|v| v.unwrap_or(0))
    }

    // Set the top height of the chain
    async fn set_top_height(&mut self, height: u64) -> Result<(), BlockchainError> {
        trace!("set new top height at {}", height);
        self.insert_into_disk(Column::Common, TOP_HEIGHT, &height.to_be_bytes())
    }
}