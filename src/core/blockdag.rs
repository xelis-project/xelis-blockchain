use std::sync::Arc;

use crate::crypto::hash::Hash;

use super::{blockchain::Blockchain, error::BlockchainError, storage::{BlockMetadata, Storage}};

fn sort_descending_by_cumulative_difficulty/*<T: AsRef<BlockMetadata>>*/(blocks: &mut Vec<Arc<BlockMetadata>>) {
    blocks.sort_by(|a, b| {
        if a.get_cumulative_difficulty() != b.get_cumulative_difficulty() {
            a.get_cumulative_difficulty().cmp(b.get_cumulative_difficulty())
        } else {
            a.get_hash().cmp(b.get_hash())
        }
    });
}

pub async fn sort_tips(blockchain: &Blockchain, tips: Vec<Hash>) -> Result<Vec<Hash>, BlockchainError> {
    if tips.len() == 0 {
        return Err(BlockchainError::ExpectedTips)
    }

    if tips.len() == 1 {
        return Ok(tips)
    }

    let storage = blockchain.get_storage().read().await;
    let mut blocks = Vec::with_capacity(tips.len());
    for hash in tips {
        let block = storage.get_block_by_hash(&hash).await?;
        blocks.push(storage.get_block_metadata(block.get_height()).await?);
    }

    sort_descending_by_cumulative_difficulty(&mut blocks);


    let mut sorted = Vec::with_capacity(blocks.len());
    for block in blocks {
        sorted.push(block.get_hash().clone());
    }

    Ok(sorted)
}

pub async fn calculate_height_at_tips(storage: &Storage, tips: &Vec<Hash>) -> Result<u64, BlockchainError> {
    let mut height = 0;
    for hash in tips {
        let block = storage.get_block_by_hash(hash).await?;
        let past_height = block.get_height();
        if height <= past_height {
            height = past_height;
        }
    }

    if tips.len() != 0 {
        height += 1;
    }
    Ok(height)
}

pub async fn find_best_tip(storage: &Storage, mut tips: Vec<Hash>, base: Hash, base_height: u64) -> Result<Hash, BlockchainError> {
    if tips.len() == 0 {
        return Err(BlockchainError::ExpectedTips)
    }

    if tips.len() == 1 {
        return Ok(tips.remove(0))
    }

    let mut blocks = Vec::with_capacity(tips.len());
    for hash in tips {
        let block = storage.get_block_by_hash(&hash).await?;
        blocks.push(storage.get_block_metadata(block.get_height()).await?);
    }

    sort_descending_by_cumulative_difficulty(&mut blocks);
    Ok(blocks.remove(0).get_hash().clone())
}