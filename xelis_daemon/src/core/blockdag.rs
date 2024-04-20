use indexmap::IndexSet;
use log::trace;
use xelis_common::{
    difficulty::CumulativeDifficulty,
    time::TimestampMillis,
    crypto::Hash,
};
use super::{    
    storage::{
        Storage,
        DifficultyProvider
    },
    error::BlockchainError,
};

// sort the scores by cumulative difficulty and, if equals, by hash value
pub fn sort_descending_by_cumulative_difficulty<T>(scores: &mut Vec<(T, CumulativeDifficulty)>)
where
    T: AsRef<Hash>,
{
    trace!("sort descending by cumulative difficulty");
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

// sort the scores by cumulative difficulty and, if equals, by hash value
pub fn sort_ascending_by_cumulative_difficulty<T>(scores: &mut Vec<(T, CumulativeDifficulty)>)
where
    T: AsRef<Hash>,
{
    trace!("sort ascending by cumulative difficulty");
    scores.sort_by(|(a_hash, a), (b_hash, b)| {
        if a != b {
            a.cmp(b)
        } else {
            a_hash.as_ref().cmp(b_hash.as_ref())
        }
    });

    if scores.len() >= 2 {
        debug_assert!(scores[0].1 <= scores[1].1);
    }
}

// Sort the TIPS by cumulative difficulty
// If the cumulative difficulty is the same, the hash value is used to sort
// Hashes are sorted in descending order
pub async fn sort_tips<S, I>(storage: &S, tips: I) -> Result<IndexSet<Hash>, BlockchainError>
where
    S: Storage,
    I: Iterator<Item = Hash> + ExactSizeIterator,
{
    trace!("sort tips");
    let tips_len = tips.len();
    match tips_len {
        0 => Err(BlockchainError::ExpectedTips),
        1 => Ok(tips.into_iter().collect()),
        _ => {
            let mut scores: Vec<(Hash, CumulativeDifficulty)> = Vec::with_capacity(tips_len);
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
    trace!("calculate height at tips");
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
    trace!("find best tip by cumulative difficulty");
    let tips_len = tips.len();
    match tips_len {
        0 => Err(BlockchainError::ExpectedTips),
        1 => Ok(tips.into_iter().next().unwrap()),
        _ => {
            let mut highest_cumulative_difficulty = CumulativeDifficulty::zero();
            let mut selected_tip = None;
            for hash in tips {
                let cumulative_difficulty = provider.get_cumulative_difficulty_for_block_hash(hash).await?;
                if highest_cumulative_difficulty < cumulative_difficulty {
                    highest_cumulative_difficulty = cumulative_difficulty;
                    selected_tip = Some(hash);
                }
            }

            selected_tip.ok_or(BlockchainError::ExpectedTips)
        }
    }
}

// Find the newest tip based on the timestamp of the blocks
pub async fn find_newest_tip_by_timestamp<'a, D, I>(provider: &D, tips: I) -> Result<(&'a Hash, TimestampMillis), BlockchainError>
where
    D: DifficultyProvider,
    I: Iterator<Item = &'a Hash> + ExactSizeIterator
{
    trace!("find newest tip by timestamp");
    let tips_len = tips.len();
    match tips_len {
        0 => Err(BlockchainError::ExpectedTips),
        1 => {
            let hash = tips.into_iter().next().unwrap();
            let timestamp = provider.get_timestamp_for_block_hash(hash).await?;
            Ok((hash, timestamp))
        },
        _ => {
            let mut timestamp = 0;
            let mut newest_tip = None;
            for hash in tips.into_iter() {
                let tip_timestamp = provider.get_timestamp_for_block_hash(hash).await?;
                if timestamp < tip_timestamp {
                    timestamp = tip_timestamp;
                    newest_tip = Some(hash);
                
                }
            }

            Ok((newest_tip.ok_or(BlockchainError::ExpectedTips)?, timestamp))
        }
    }
}