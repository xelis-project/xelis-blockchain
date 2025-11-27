mod v1;
mod v2;

use std::{
    cmp::Ordering,
    collections::{HashSet, VecDeque}
};

use futures::{StreamExt, TryStreamExt, stream};
use indexmap::IndexSet;
use itertools::Either;
use log::{debug, error, trace, warn};
use xelis_common::{
    block::{BlockVersion, TopoHeight, get_combined_hash_for_tips},
    crypto::Hash,
    difficulty::{CumulativeDifficulty, Difficulty},
    time::TimestampMillis
};
use crate::{config::STABLE_LIMIT, core::storage::*};

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
        match b.cmp(a) {
            Ordering::Equal => b_hash.as_ref().cmp(a_hash.as_ref()), // tie-break by hash desc
            ord => ord,
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
        match a.cmp(b) {
            Ordering::Equal => a_hash.as_ref().cmp(b_hash.as_ref()), // tie-break by hash asc
            ord => ord,
        }
    });

    if scores.len() >= 2 {
        debug_assert!(scores[0].1 <= scores[1].1);
    }
}

// Sort the TIPS by cumulative difficulty
// If the cumulative difficulty is the same, the hash value is used to sort
// Hashes are sorted in descending order
pub async fn sort_tips<S, I>(storage: &S, tips: I) -> Result<impl Iterator<Item = Hash> + ExactSizeIterator, BlockchainError>
where
    S: Storage,
    I: Iterator<Item = Hash> + ExactSizeIterator,
{
    trace!("sort tips");
    let tips_len = tips.len();
    match tips_len {
        0 => Err(BlockchainError::ExpectedTips),
        1 => Ok(Either::Left(tips)),
        _ => {
            let mut scores: Vec<(Hash, CumulativeDifficulty)> = Vec::with_capacity(tips_len);
            for hash in tips {
                let cumulative_difficulty = storage.get_cumulative_difficulty_for_block_hash(&hash).await?;
                scores.push((hash, cumulative_difficulty));
            }

            sort_descending_by_cumulative_difficulty(&mut scores);
            Ok(Either::Right(scores.into_iter().map(|(hash, _)| hash)))
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

// Verify if the block is a sync block
// A sync block is a block that is ordered and has the highest cumulative difficulty at its height
// It is used to determine if the block is a stable block or not
pub async fn is_sync_block_at_height<P>(
    provider: &P,
    hash: &Hash,
    height: u64,
) -> Result<bool, BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider + BlocksAtHeightProvider + PrunedTopoheightProvider,
{
    trace!("is sync block {} at height {}", hash, height);

    let block_height = provider.get_height_for_block_hash(hash).await?;
    // genesis block is a sync block
    if block_height == 0 {
        trace!("Block {} at height {} is a sync block because it can only be the genesis block", hash, block_height);
        return Ok(true)
    }

    // block must be ordered and in stable height
    if block_height + STABLE_LIMIT > height || !provider.is_block_topological_ordered(hash).await? {
        trace!("Block {} at height {} is not a sync block, it is not in stable height", hash, block_height);
        return Ok(false)
    }

    // We are only pruning at sync block
    if let Some(pruned_topo) = provider.get_pruned_topoheight().await? {
        let topoheight = provider.get_topo_height_for_hash(hash).await?;
        if pruned_topo == topoheight {
            // We only prune at sync block, if block is pruned, it is a sync block
            trace!("Block {} at height {} is a sync block, it is pruned", hash, block_height);
            return Ok(true)
        }
    }

    // if block is alone at its height, it is a sync block
    let tips_at_height = provider.get_blocks_at_height(block_height).await?;

    // if block is not alone at its height and they are ordered (not orphaned), it can't be a sync block
    for hash_at_height in tips_at_height {
        if *hash != hash_at_height && provider.is_block_topological_ordered(&hash_at_height).await? {
            trace!("Block {} at height {} is not a sync block, it has more than 1 block at its height", hash, block_height);
            return Ok(false)
        }
    }

    // precompute once
    let sync_cd = provider.get_cumulative_difficulty_for_block_hash(hash).await?;

    // scan window below without allocating a set; early-exit on first violating block
    let stable_point = if block_height >= STABLE_LIMIT {
        block_height - STABLE_LIMIT
    } else {
        STABLE_LIMIT - block_height
    };

    let mut i = block_height.saturating_sub(1);
    while i >= stable_point && i != 0 {
        let blocks = provider.get_blocks_at_height(i).await?;
        for pre in blocks {
            // compare only with ordered blocks
            if provider.is_block_topological_ordered(&pre).await? {
                let cd = provider.get_cumulative_difficulty_for_block_hash(&pre).await?;
                if cd >= sync_cd {
                    debug!(
                        "Block {} at height {} is not a sync block; {} at height {} has >= cumulative difficulty",
                        hash, block_height, pre, i
                    );
                    return Ok(false);
                }
            }
        }
        i -= 1;
    }

    Ok(true)
}

// a block is a side block if its ordered and its block height is less than or equal to height of past 8 topographical blocks
pub async fn is_side_block_internal<P>(provider: &P, hash: &Hash, block_topoheight: Option<u64>, current_topoheight: TopoHeight) -> Result<bool, BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider
{
    trace!("is block {} a side block", hash);
    let topoheight = match block_topoheight {
        Some(v) => v,
        None => {
            if !provider.is_block_topological_ordered(hash).await? {
                return Ok(false)
            }

            provider.get_topo_height_for_hash(hash).await?
        }
    };

    // genesis block can't be a side block
    if topoheight == 0 || topoheight > current_topoheight {
        return Ok(false)
    }

    let height = provider.get_height_for_block_hash(hash).await?;

    // verify if there is a block with height higher than this block in past 8 topo blocks
    let mut counter = 0;
    let mut i = topoheight - 1;
    while counter < STABLE_LIMIT && i > 0 {
        let hash = provider.get_hash_at_topo_height(i).await?;
        let previous_height = provider.get_height_for_block_hash(&hash).await?;

        if height <= previous_height {
            return Ok(true)
        }
        counter += 1;
        i -= 1;
    }

    Ok(false)
}

pub async fn find_tip_base<P>(provider: &P, hash: &Hash, height: u64, pruned_topoheight: TopoHeight) -> Result<(Hash, u64), BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider + BlocksAtHeightProvider + PrunedTopoheightProvider + CacheProvider
{
    debug!("find tip base for {} at height {}", hash, height);
    let chain_cache = provider.chain_cache().await;

    debug!("accessing tip base cache for {} at height {}", hash, height);
    let mut cache = chain_cache.tip_base_cache.lock().await;
    debug!("tip base cache locked for {} at height {}", hash, height);

    let mut stack: VecDeque<Hash> = VecDeque::new();
    stack.push_back(hash.clone());

    let mut bases: IndexSet<(Hash, u64)> = IndexSet::new();
    let mut processed = HashSet::new();

    'main: while let Some(current_hash) = stack.pop_back() {
        trace!("Finding tip base for {} at height {}", current_hash, height);
        processed.insert(current_hash.clone());
        if pruned_topoheight > 0 && provider.is_block_topological_ordered(&current_hash).await? {
            let topoheight = provider.get_topo_height_for_hash(&current_hash).await?;
            // Node is pruned, we only prune chain to stable height / sync block so we can return the hash
            if topoheight <= pruned_topoheight {
                let block_height = provider.get_height_for_block_hash(&current_hash).await?;
                debug!("Node is pruned, returns tip {} at {} as stable tip base", current_hash, block_height);
                bases.insert((current_hash.clone(), block_height));
                continue 'main;
            }
        }

        // first, check if we have it in cache
        if let Some((base_hash, base_height)) = cache.get(&(current_hash.clone(), height)) {
            trace!("Tip Base for {} at height {} found in cache: {} for height {}", current_hash, height, base_hash, base_height);
            bases.insert((base_hash.clone(), *base_height));
            continue 'main;
        }

        let tips = provider.get_past_blocks_for_block_hash(&current_hash).await?;
        let tips_count = tips.len();
        if tips_count == 0 { // only genesis block can have 0 tips saved
            // save in cache
            cache.put((hash.clone(), height), (current_hash.clone(), height));
            bases.insert((current_hash.clone(), 0));
            continue 'main;
        }

        for tip_hash in tips.iter() {
            if pruned_topoheight > 0 && provider.is_block_topological_ordered(&tip_hash).await? {
                let topoheight = provider.get_topo_height_for_hash(&tip_hash).await?;
                // Node is pruned, we only prune chain to stable height / sync block so we can return the hash
                if topoheight <= pruned_topoheight {
                    let block_height = provider.get_height_for_block_hash(&tip_hash).await?;
                    debug!("Node is pruned, returns tip {} at {} as stable tip base", tip_hash, block_height);
                    bases.insert((tip_hash.clone(), block_height));
                    continue 'main;
                }
            }

            // if block is sync, it is a tip base
            if is_sync_block_at_height(provider, &tip_hash, height).await? {
                let block_height = provider.get_height_for_block_hash(&tip_hash).await?;
                // save in cache
                cache.put((hash.clone(), height), (tip_hash.clone(), block_height));
                bases.insert((tip_hash.clone(), block_height));
                continue 'main;
            }

            if !processed.contains(tip_hash) {
                // Tip was not sync, we need to find its tip base too
                stack.push_back(tip_hash.clone());
            }
        }
    }

    if bases.is_empty() {
        error!("Tip base for {} at height {} not found", hash, height);
        return Err(BlockchainError::ExpectedTips)
    }

    // now we sort descending by height and return the last element deleted
    bases.sort_by(|(_, a), (_, b)| b.cmp(a));
    debug_assert!(bases[0].1 >= bases[bases.len() - 1].1);

    let (base_hash, base_height) = bases.pop().ok_or(BlockchainError::ExpectedTips)?;

    // save in cache
    cache.put((hash.clone(), height), (base_hash.clone(), base_height));
    trace!("Tip Base for {} at height {} found: {} for height {}", hash, height, base_hash, base_height);

    Ok((base_hash, base_height))
}

// find the common base (block hash and block height) of all tips
pub async fn find_common_base<'a, P, I>(provider: &P, tips: I) -> Result<(Hash, u64), BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider + BlocksAtHeightProvider + PrunedTopoheightProvider + CacheProvider,
    I: IntoIterator<Item = &'a Hash> + Copy,
{
    debug!("find common base for tips {}", tips.into_iter().map(|h| h.to_string()).collect::<Vec<String>>().join(", "));
    let chain_cache = provider.chain_cache().await;

    debug!("accessing common base cache");
    let mut cache = chain_cache.common_base_cache.lock().await;
    debug!("common base cache locked");

    let combined_tips = get_combined_hash_for_tips(tips.into_iter());
    if let Some((hash, height)) = cache.get(&combined_tips) {
        debug!("Common base found in cache: {} at height {}", hash, height);
        return Ok((hash.clone(), *height))
    }

    let mut best_height = 0;
    // first, we check the best (highest) height of all tips
    for hash in tips.into_iter() {
        let height = provider.get_height_for_block_hash(hash).await?;
        if height > best_height {
            best_height = height;
        }
    }

    let pruned_topoheight = provider.get_pruned_topoheight().await?
        .unwrap_or(0);
    let mut bases = Vec::new();
    for hash in tips.into_iter() {
        trace!("Searching tip base for {}", hash);
        bases.push(find_tip_base(provider, hash, best_height, pruned_topoheight).await?);
    }

    // check that we have at least one value
    if bases.is_empty() {
        error!("bases list is empty");
        return Err(BlockchainError::ExpectedTips)
    }

    // sort it descending by height
    // a = 5, b = 6, b.cmp(a) -> Ordering::Greater
    bases.sort_by(|(_, a), (_, b)| b.cmp(a));
    debug_assert!(bases[0].1 >= bases[bases.len() - 1].1);

    // retrieve the first block hash with its height
    // we delete the last element because we sorted it descending
    // and we want the lowest height
    let (base_hash, base_height) = bases.remove(bases.len() - 1);
    debug!("Common base {} with height {} on {}", base_hash, base_height, bases.len() + 1);

    // save in cache
    cache.put(combined_tips, (base_hash.clone(), base_height));

    Ok((base_hash, base_height))
}

pub async fn build_reachability<P: DifficultyProvider>(provider: &P, hash: Hash) -> Result<HashSet<Hash>, BlockchainError> {
    let mut set = HashSet::new();
    let mut stack: VecDeque<(Hash, u64)> = VecDeque::new();
    stack.push_back((hash, 0));

    while let Some((current_hash, current_level)) = stack.pop_back() {
        if current_level >= 2 * STABLE_LIMIT {
            trace!("Level limit reached, adding {}", current_hash);
            set.insert(current_hash);
        } else {
            trace!("Level {} reached with hash {}", current_level, current_hash);
            let tips = provider.get_past_blocks_for_block_hash(&current_hash).await?;
            set.insert(current_hash);
            for past_hash in tips.iter() {
                if !set.contains(past_hash) {
                    stack.push_back((past_hash.clone(), current_level + 1));
                }
            }
        }
    }

    Ok(set)
}

// this function check that a TIP cannot be refered as past block in another TIP
pub async fn verify_non_reachability<P: DifficultyProvider>(provider: &P, tips: &IndexSet<Hash>) -> Result<bool, BlockchainError> {
    trace!("Verifying non reachability for block");
    let tips_count = tips.len();
    let mut reach = Vec::with_capacity(tips_count);
    for hash in tips {
        let set = build_reachability(provider, hash.clone()).await?;
        reach.push(set);
    }

    for i in 0..tips_count {
        for j in 0..tips_count {
            // if a tip can be referenced as another's past block, its not a tip
            if i != j && reach[j].contains(&tips[i]) {
                debug!("Tip {} (index {}) is reachable from tip {} (index {})", tips[i], i, tips[j], j);
                trace!("reach: {}", reach[j].iter().map(|x| x.to_string()).collect::<Vec<String>>().join(", "));
                return Ok(false)
            }
        }
    }
    Ok(true)
}

// Search the lowest height available from the tips of a block hash
// We go through all tips and their tips until we have no unordered block left
// Max deviation is used to stop searching too deep
pub async fn find_lowest_height_from_mainchain<P>(provider: &P, hash: Hash, max_deviation: u64) -> Result<Option<u64>, BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider
{
    // Lowest height found from mainchain
    let mut lowest_height = None;
    // Current stack of blocks to process
    let mut stack: VecDeque<(Hash, u64)> = VecDeque::new();
    // Because several blocks can have the same tips,
    // prevent to process a block twice
    let mut processed = HashSet::new();

    stack.push_back((hash, 0));

    while let Some((current_hash, depth)) = stack.pop_back() {
        if depth > max_deviation {
            debug!("Max deviation {} reached when searching lowest height from mainchain for block {}", max_deviation, current_hash);
            continue;
        }

        if processed.contains(&current_hash) {
            continue;
        }

        let tips = provider.get_past_blocks_for_block_hash(&current_hash).await?;
        for tip_hash in tips.iter() {
            if provider.is_block_topological_ordered(tip_hash).await? {
                let height = provider.get_height_for_block_hash(tip_hash).await?;
                if lowest_height.is_none_or(|h| h > height) {
                    lowest_height = Some(height);
                }
            } else {
                stack.push_back((tip_hash.clone(), depth + 1));
            }
        }
        processed.insert(current_hash);
    }

    Ok(lowest_height)
}

// Search the lowest height available from this block hash
// This function is used to calculate the distance from main chain
// It will recursively search all tips and their height
// If a tip is not ordered, we will search its tips until we find an ordered block
pub async fn calculate_distance_from_main_chain<P>(provider: &P, hash: &Hash, max_deviation: u64) -> Result<Option<u64>, BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider
{
    if provider.is_block_topological_ordered(hash).await? {
        let height = provider.get_height_for_block_hash(hash).await?;
        debug!("calculate_distance: Block {} is at height {}", hash, height);
        return Ok(Some(height))
    }

    debug!("calculate_distance: Block {} is not ordered, calculate distance from main chain", hash);
    let lowest_height = find_lowest_height_from_mainchain(provider, hash.clone(), max_deviation).await?;

    debug!("calculate_distance: lowest height found is {:?}", lowest_height);
    Ok(lowest_height)
}

// Verify if the block is not too far from mainchain
// We calculate the distance from mainchain and compare it to the height
pub async fn is_near_enough_from_main_chain<P>(provider: &P, hash: &Hash, block_height: u64, max_deviation: u64) -> Result<bool, BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider
{
    let Some(lowest_ordered_height) = calculate_distance_from_main_chain(provider, hash, max_deviation).await? else {
        return Ok(false);
    };

    debug!("distance for block {}: lowest is {} at chain height {}", hash, lowest_ordered_height, block_height);

    // If the lowest ordered height is below or equal to current chain height
    // and that we have a difference bigger than our maximum deviation
    if block_height.checked_sub(lowest_ordered_height).is_none_or(|v| v >= max_deviation) {
        warn!(
            "Block {} with height {} deviates too far: lowest ordered height {}, max deviation: {}",
            hash, block_height, lowest_ordered_height, max_deviation
        );
        return Ok(false)
    }

    Ok(true)
}

// find the sum of work done using GHOSTDAG k-cluster
// Only blocks in the "blue set" (well-connected, honest blocks) contribute to cumulative difficulty.
// This prevents parasite chain attacks where attackers incrementally reference the main chain
// to steal cumulative difficulty without being referenced back.
pub async fn find_tip_work_score<P>(
    provider: &P,
    block_hash: &Hash,
    block_tips: &IndexSet<Hash>,
    block_difficulty: Option<Difficulty>,
    block_version: BlockVersion,
    base_block: &Hash,
    base_block_height: u64,
) -> Result<(HashSet<Hash>, CumulativeDifficulty), BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider + CacheProvider
{
    trace!("find tip work score for {} at base {}", block_hash, base_block);
    let cache_key = (block_hash.clone(), base_block.clone(), base_block_height);

    {
        let chain_cache = provider.chain_cache().await;

        debug!("accessing tip work score cache for {} at height {}", block_hash, base_block_height);
        let mut cache = chain_cache.tip_work_score_cache.lock().await;
        if let Some(value) = cache.get(&cache_key) {
            trace!("Found tip work score in cache: set [{}], height: {}", value.0.iter().map(|h| h.to_string()).collect::<Vec<String>>().join(", "), value.1);
            return Ok(value.clone())
        }
    }


    let (blue_set, score) = match block_version {
        BlockVersion::V0 | BlockVersion::V1 | BlockVersion::V2 => v1::find_tip_work_score(provider, block_hash, block_tips.iter(), block_difficulty, base_block).await,
        BlockVersion::V3 => v2::find_tip_work_score(provider, block_hash, block_tips, block_difficulty, base_block, base_block_height).await,
    }?;

    // save this result in cache
    {
        let chain_cache = provider.chain_cache().await;
        let mut cache = chain_cache.tip_work_score_cache.lock().await;
        cache.put(cache_key, (blue_set.clone(), score));
    }

    Ok((blue_set, score))
}

// find the best tip (highest cumulative difficulty)
// We get their cumulative difficulty and sort them then take the first one
pub async fn find_best_tip<'a, P: DifficultyProvider + DagOrderProvider + CacheProvider + Send + Sync>(
    provider: &P,
    tips: &'a HashSet<Hash>,
    base: &Hash,
    base_height: u64,
    concurrency: usize,
    block_version: BlockVersion,
) -> Result<&'a Hash, BlockchainError> {
    if tips.len() == 0 {
        return Err(BlockchainError::ExpectedTips)
    }

    let mut scores = stream::iter(tips.iter())
        .map(|hash| async move {
            let block_tips = provider.get_past_blocks_for_block_hash(hash).await?;
            let (_, cumulative_difficulty) = find_tip_work_score(provider, hash, &block_tips, None, block_version, base, base_height).await?;

            Ok::<_, BlockchainError>((hash, cumulative_difficulty))
        })
        .boxed()
        .buffer_unordered(concurrency)
        .try_collect()
        .await?;

    sort_descending_by_cumulative_difficulty(&mut scores);
    let (best_tip, _) = scores[0];
    Ok(best_tip)
}

// this function generate a DAG partial order into a full order.
// hash represents the best tip (biggest cumulative difficulty)
// base represents the block hash of a block already ordered and in stable height
// the full order is re generated each time a new block is added based on new TIPS
pub async fn generate_full_order<P>(provider: &P, hash: &Hash, base: &Hash, base_height: u64, base_topo_height: TopoHeight, block_version: BlockVersion) -> Result<IndexSet<Hash>, BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider + CacheProvider
{
    trace!("generate full order for {} with base {} version {}", hash, base, block_version);

    match block_version {
        BlockVersion::V0 | BlockVersion::V1 | BlockVersion::V2 => v1::generate_full_order(provider, hash, base, base_height, base_topo_height).await,
        BlockVersion::V3 => v2::generate_full_order(provider, hash, base, base_height, base_topo_height).await,
    }
}

// confirms whether the actual tip difficulty is withing 9% deviation with best tip (reference)
pub async fn validate_tips<P: DifficultyProvider>(provider: &P, best_tip: &Hash, tip: &Hash) -> Result<bool, BlockchainError> {
    const MAX_DEVIATION: Difficulty = Difficulty::from_u64(91);
    const PERCENTAGE: Difficulty = Difficulty::from_u64(100);

    let best_difficulty = provider.get_difficulty_for_block_hash(best_tip).await?;
    let block_difficulty = provider.get_difficulty_for_block_hash(tip).await?;

    Ok(best_difficulty * MAX_DEVIATION / PERCENTAGE < block_difficulty)
}