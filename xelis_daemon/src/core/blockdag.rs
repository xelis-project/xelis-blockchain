use xelis_common::crypto::hash::Hash;
use crate::storage::Storage;
use super::error::BlockchainError;

// sort the scores by cumulative difficulty and, if equals, by hash value
pub fn sort_descending_by_cumulative_difficulty(scores: &mut Vec<(&Hash, u64)>) {
    scores.sort_by(|(a_hash, a), (b_hash, b)| {
        if a != b {
            b.cmp(a)
        } else {
            b_hash.cmp(a_hash)
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
        let cumulative_difficulty = storage.get_cumulative_difficulty_for_block(hash).await?;
        scores.push((hash, cumulative_difficulty));
    }

    sort_descending_by_cumulative_difficulty(&mut scores);

    let mut sorted = Vec::with_capacity(scores.len());
    for (hash, _) in scores {
        sorted.push(hash.clone());
    }

    Ok(sorted)
}

// determine he lowest height possible based on tips and do N+1
pub async fn calculate_height_at_tips(storage: &Storage, tips: &Vec<Hash>) -> Result<u64, BlockchainError> {
    let mut height = 0;
    for hash in tips {
        let past_height = storage.get_height_for_block(hash).await?;
        if height <= past_height {
            height = past_height;
        }
    }

    if tips.len() != 0 {
        height += 1;
    }
    Ok(height)
}

// find the best tip based on cumulative difficulty of the blocks
pub async fn find_best_tip_by_cumulative_difficulty<'a>(storage: &Storage, tips: &'a Vec<Hash>) -> Result<&'a Hash, BlockchainError> {
    if tips.len() == 0 {
        return Err(BlockchainError::ExpectedTips)
    }

    if tips.len() == 1 {
        return Ok(&tips[0])
    }

    let mut scores = Vec::with_capacity(tips.len());
    for hash in tips {
        let cumulative_difficulty = storage.get_cumulative_difficulty_for_block(hash).await?;
        scores.push((hash, cumulative_difficulty));
    }

    sort_descending_by_cumulative_difficulty(&mut scores);
    let (best_tip, _) = scores[0];
    Ok(best_tip)
}