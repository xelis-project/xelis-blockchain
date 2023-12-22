use indexmap::IndexSet;
use xelis_common::block::Difficulty;
use xelis_common::crypto::hash::Hash;
use super::storage::Storage;
use super::{error::BlockchainError, storage::DifficultyProvider};

// sort the scores by cumulative difficulty and, if equals, by hash value
pub fn sort_descending_by_cumulative_difficulty<T>(scores: &mut Vec<(T, Difficulty)>)
where
    T: AsRef<Hash>,
{
    scores.sort_by(|(a_hash, a), (b_hash, b)| {
        if a != b {
            b.cmp(a)
        } else {
            b_hash.as_ref().cmp(a_hash.as_ref())
        }
    });

    if scores.len() >= 2 {
        debug_assert!(scores[0].1 >= scores[1].1);
    }
}

pub async fn sort_tips<S, I>(storage: &S, tips: I) -> Result<IndexSet<Hash>, BlockchainError>
where
    S: Storage,
    I: Iterator<Item = Hash> + ExactSizeIterator,
{
    let tips_len = tips.len();
    match tips_len {
        0 => Err(BlockchainError::ExpectedTips),
        1 => Ok(tips.into_iter().collect()),
        _ => {
            let mut scores: Vec<(Hash, Difficulty)> = Vec::with_capacity(tips_len);
            for hash in tips {
                let cumulative_difficulty = storage.get_cumulative_difficulty_for_block_hash(&hash).await?;
                scores.push((hash, cumulative_difficulty));
            }

            sort_descending_by_cumulative_difficulty(&mut scores);
            Ok(scores.into_iter().map(|(hash, _)| hash).collect())
        }
    }
}

// determine he lowest height possible based on tips and do N+1
pub async fn calculate_height_at_tips<'a, D, I>(provider: &D, tips: I) -> Result<u64, BlockchainError>
where
    D: DifficultyProvider,
    I: Iterator<Item = &'a Hash> + ExactSizeIterator
{
    let mut height = 0;
    let tips_len = tips.len();
    for hash in tips {
        let past_height = provider.get_height_for_block_hash(hash).await?;
        if height <= past_height {
            height = past_height;
        }
    }

    if tips_len != 0 {
        height += 1;
    }
    Ok(height)
}

// find the best tip based on cumulative difficulty of the blocks
pub async fn find_best_tip_by_cumulative_difficulty<'a, D, I>(provider: &D, tips: I) -> Result<&'a Hash, BlockchainError>
where
    D: DifficultyProvider,
    I: Iterator<Item = &'a Hash> + ExactSizeIterator
{
    let tips_len = tips.len();
    match tips_len {
        0 => Err(BlockchainError::ExpectedTips),
        1 => Ok(tips.into_iter().next().unwrap()),
        _ => {
            let mut scores = Vec::with_capacity(tips_len);
            for hash in tips {
                let cumulative_difficulty = provider.get_cumulative_difficulty_for_block_hash(hash).await?;
                scores.push((hash, cumulative_difficulty));
            }

            sort_descending_by_cumulative_difficulty(&mut scores);
            let (best_tip, _) = scores[0];
            Ok(best_tip)
        }
    }
}