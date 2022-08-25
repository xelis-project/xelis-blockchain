use super::{error::BlockchainError, storage::{Storage, BlockMetadata}};
use crate::crypto::hash::Hash;
use std::sync::Arc;

fn sort_descending_by_cumulative_difficulty(scores: &mut Vec<(&Hash, Arc<BlockMetadata>)>) {
    scores.sort_by(|(a_hash, a), (b_hash, b)| {
        if a.get_cumulative_difficulty() != b.get_cumulative_difficulty() {
            a.get_cumulative_difficulty().cmp(b.get_cumulative_difficulty())
        } else {
            a_hash.cmp(b_hash)
        }
    });
}

// TODO Refactor
pub async fn sort_tips(storage: &Storage, tips: &Vec<Hash>) -> Result<Vec<Hash>, BlockchainError> {
    if tips.len() == 0 {
        return Err(BlockchainError::ExpectedTips)
    }

    if tips.len() == 1 {
        return Ok(tips.clone())
    }

    let mut scores = Vec::with_capacity(tips.len());
    for hash in tips {
        let block = storage.get_block_by_hash(hash).await?;
        let metadata = storage.get_block_metadata(block.get_height()).await?;
        scores.push((hash, metadata));
    }

    sort_descending_by_cumulative_difficulty(&mut scores);


    let mut sorted = Vec::with_capacity(scores.len());
    for (hash, _) in scores {
        sorted.push(hash.clone());
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

pub async fn find_best_tip_by_cumulative_difficulty<'a>(storage: &Storage, tips: &'a Vec<Hash>) -> Result<&'a Hash, BlockchainError> {
    if tips.len() == 0 {
        return Err(BlockchainError::ExpectedTips)
    }

    if tips.len() == 1 {
        return Ok(&tips[0])
    }

    let mut scores = Vec::with_capacity(tips.len());
    for hash in tips {
        let block = storage.get_block_by_hash(&hash).await?;
        let metadata = storage.get_block_metadata(block.get_height()).await?;
        scores.push((hash, metadata));
    }

    sort_descending_by_cumulative_difficulty(&mut scores);
    let (best_tip, _) = scores[0];
    Ok(best_tip)
}