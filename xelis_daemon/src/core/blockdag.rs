use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet, VecDeque}
};

use indexmap::IndexSet;
use itertools::Either;
use log::{debug, error, trace, warn};
use xelis_common::{
    block::{TopoHeight, get_combined_hash_for_tips},
    crypto::Hash,
    difficulty::{CumulativeDifficulty, Difficulty},
    time::TimestampMillis
};
use crate::{config::{STABLE_LIMIT, GHOSTDAG_K}, core::storage::*};

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

// GHOSTDAG: Calculate the "blue set" - blocks that are well-connected to the selected chain
// This implements the PHANTOM/GHOSTDAG protocol's k-cluster algorithm to identify honest blocks.
// 
// A block is "blue" (honest) if its anticone size (blocks not mutually reachable) is <= k.
// Blocks with anticone > k are "red" (potential attackers) and excluded from cumulative difficulty.
//
// This prevents parasite chain attacks where an attacker incrementally references the main chain
// to steal its cumulative difficulty without being referenced back.
//
// Algorithm:
// 1. Start with the selected chain (highest cumulative difficulty path)
// 2. For each candidate block, calculate its anticone size relative to the blue set
// 3. If anticone_size <= k, add to blue set (honest)
// 4. If anticone_size > k, mark as red (potential attacker, excluded)
//
// Reference: "PHANTOM: A Scalable BlockDAG protocol" (Sompolinsky & Zohar)
// https://eprint.iacr.org/2018/104.pdf
pub async fn calculate_blue_set<P>(
    provider: &P,
    block_hash: &Hash,
    block_tips: &IndexSet<Hash>,
    base_topoheight: TopoHeight
) -> Result<HashSet<Hash>, BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider + CacheProvider
{
    let chain_cache = provider.chain_cache().await;
    let mut blue_set_cache = chain_cache.blue_set_cache.lock().await;

    // Check cache first
    let cache_key = (block_hash.clone(), base_topoheight);
    if let Some(cached) = blue_set_cache.get(&cache_key) {
        trace!("Blue set for block {} found in cache ({} blocks)", block_hash, cached.len());
        return Ok(cached.clone());
    }

    trace!("Calculating GHOSTDAG blue set for block {} with k={}", block_hash, GHOSTDAG_K);

    // Blue set: blocks that are "honest" (well-connected to the main chain)
    let mut blue_set = HashSet::new();
    blue_set.insert(block_hash.clone());

    // Cache for past sets: past(B) = all ancestors of B (not including B itself)
    // This is the key optimization - we build past sets incrementally
    let mut past_cache = HashMap::new();
    
    // Build past set for the block being validated
    // Past of new block = all ancestors reachable from its parents
    let block_past = build_past_set(provider, block_tips, base_topoheight).await?;
    past_cache.insert(block_hash.clone(), block_past);

    // Queue for candidates to evaluate (BFS order)
    let mut queue: VecDeque<Hash> = VecDeque::from_iter(block_tips.iter().cloned());
    let mut processed = HashSet::new();

    while let Some(candidate) = queue.pop_front() {
        // Skip if already blue or already evaluated
        if blue_set.contains(&candidate) || !processed.insert(candidate.clone()) {
            continue;
        }

        // Check topoheight boundary (don't process blocks below base)
        if provider.is_block_topological_ordered(&candidate).await? {
            let topo = provider.get_topo_height_for_hash(&candidate).await?;
            if topo < base_topoheight {
                trace!("Block {} below base topoheight {}, skipping", candidate, base_topoheight);
                continue;
            }
        }

        // Get or build past set for candidate
        if !past_cache.contains_key(&candidate) {
            let tips = provider.get_past_blocks_for_block_hash(&candidate).await?;
            let candidate_past = build_past_set(provider, &tips, base_topoheight).await?;
            past_cache.insert(candidate.clone(), candidate_past);
        }

        // Calculate anticone: blocks in blue_set that are NOT mutually reachable with candidate
        // Two blocks are mutually reachable if one is in the past of the other
        let candidate_past = past_cache.get(&candidate)
            .ok_or(BlockchainError::CorruptedData)?;
        let mut anticone_size = 0;

        for blue_block in blue_set.iter() {
            if blue_block == &candidate {
                continue;
            }

            // Get past of blue block
            let blue_past = past_cache.get(blue_block)
                .ok_or(BlockchainError::CorruptedData)?;

            // Check if they're mutually reachable:
            // - candidate is in blue block's past, OR
            // - blue block is in candidate's past
            let mutually_reachable = blue_past.contains(&candidate) || candidate_past.contains(blue_block);
            if !mutually_reachable {
                anticone_size += 1;
                // Early exit optimization
                if anticone_size > GHOSTDAG_K {
                    break;
                }
            }
        }

        trace!(
            "Block {} anticone size: {} (k={}, blue_set: {}, past: {})",
            candidate, anticone_size, GHOSTDAG_K, blue_set.len(), candidate_past.len()
        );

        // If anticone size <= k, this block is blue (honest)
        if anticone_size <= GHOSTDAG_K {
            blue_set.insert(candidate.clone());

            // Add this block's tips to the candidate queue 
            let tips = provider.get_past_blocks_for_block_hash(&candidate).await?;
            for tip in tips.iter() {
                if !blue_set.contains(tip) && !processed.contains(tip) {
                    queue.push_back(tip.clone());
                }
            }
        } else {
            // Block is red (potential attacker), don't add to blue set
            debug!(
                "Block {} marked as RED (anticone {} > k={}), excluding from cumulative difficulty",
                candidate, anticone_size, GHOSTDAG_K
            );
        }
    }

    debug!(
        "GHOSTDAG blue set complete for {}: {} blue blocks, {} cached past sets (k={})",
        block_hash, blue_set.len(), past_cache.len(), GHOSTDAG_K
    );

    // Cache the result
    blue_set_cache.put(cache_key, blue_set.clone());

    Ok(blue_set)
}

// Build past set for a block given its immediate parents (tips)
// Returns: all ancestors reachable from tips (not including tips themselves)
// Uses BFS to traverse the DAG backwards, respecting base_topoheight boundary
async fn build_past_set<P>(
    provider: &P,
    tips: &IndexSet<Hash>,
    base_topoheight: TopoHeight
) -> Result<HashSet<Hash>, BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider
{
    let mut past = HashSet::new();
    let mut queue: VecDeque<Hash> = VecDeque::from_iter(tips.iter().cloned());

    while let Some(current) = queue.pop_front() {
        // Skip if already in past
        if past.contains(&current) {
            continue;
        }

        // Check topoheight boundary
        if provider.is_block_topological_ordered(&current).await? {
            let topo = provider.get_topo_height_for_hash(&current).await?;
            if topo < base_topoheight {
                continue;
            }
        }

        // Add to past
        past.insert(current.clone());

        // Queue its parents
        let current_tips = provider.get_past_blocks_for_block_hash(&current).await?;
        for tip in current_tips.iter() {
            if !past.contains(tip) {
                queue.push_back(tip.clone());
            }
        }
    }

    Ok(past)
}

// Find tip work score internal for a block hash
// this will recursively find all tips and their difficulty
pub async fn find_tip_work_score_internal<'a, P>(provider: &P, map: &mut HashMap<Hash, CumulativeDifficulty>, hash: &'a Hash, base_topoheight: TopoHeight) -> Result<(), BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider
{
    trace!("Finding tip work score for {}", hash);

    let mut stack: VecDeque<Hash> = VecDeque::new();
    stack.push_back(hash.clone());

    while let Some(current_hash) = stack.pop_back() {
        // if not already processed
        if !map.contains_key(&current_hash) {
            // add its difficulty
            map.insert(current_hash.clone(), provider.get_difficulty_for_block_hash(&current_hash).await?.into());

            // process its tips
            let tips = provider.get_past_blocks_for_block_hash(&current_hash).await?;
            for tip_hash in tips.iter() {
                // if tip_hash not already processed
                // we check if it is ordered and its topoheight is >= base_topoheight
                // or not ordered at all
                if !map.contains_key(tip_hash) {
                    let is_ordered = provider.is_block_topological_ordered(tip_hash).await?;
                    if !is_ordered || provider.get_topo_height_for_hash(tip_hash).await? >= base_topoheight {
                        stack.push_back(tip_hash.clone());
                    }
                }
            }
        }
    }

    Ok(())
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
    base_block: &Hash,
    base_block_height: u64
) -> Result<(HashSet<Hash>, CumulativeDifficulty), BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider + CacheProvider
{
    trace!("find tip work score for {} at base {}", block_hash, base_block);
    let chain_cache = provider.chain_cache().await;

    debug!("accessing tip work score cache for {} at height {}", block_hash, base_block_height);
    let mut cache = chain_cache.tip_work_score_cache.lock().await;
    if let Some(value) = cache.get(&(block_hash.clone(), base_block.clone(), base_block_height)) {
        trace!("Found tip work score in cache: set [{}], height: {}", value.0.iter().map(|h| h.to_string()).collect::<Vec<String>>().join(", "), value.1);
        return Ok(value.clone())
    }

    let block_difficulty = if let Some(diff) = block_difficulty {
        diff
    } else {
        provider.get_difficulty_for_block_hash(&block_hash).await?
    };

    let base_topoheight = provider.get_topo_height_for_hash(base_block).await?;

    // Calculate blue set using GHOSTDAG k-cluster algorithm
    let blue_set = calculate_blue_set(provider, block_hash, block_tips, base_topoheight).await?;
    
    debug!("Blue set for block {} contains {} blocks", block_hash, blue_set.len());
    
    // Only count difficulty from blocks in the blue set
    let mut score = CumulativeDifficulty::zero();
    let mut difficulty_map: HashMap<Hash, CumulativeDifficulty> = HashMap::new();
    
    // Add current block's difficulty
    score += CumulativeDifficulty::from(block_difficulty);
    difficulty_map.insert(block_hash.clone(), block_difficulty.into());
    
    // Add difficulty only from blue blocks
    for hash in &blue_set {
        if hash != block_hash && !difficulty_map.contains_key(hash) {
            let diff = provider.get_difficulty_for_block_hash(hash).await?;
            score += CumulativeDifficulty::from(diff);
            difficulty_map.insert(hash.clone(), diff.into());
        }
    }
    
    // Add base block if different
    if base_block != block_hash && blue_set.contains(base_block) {
        if !difficulty_map.contains_key(base_block) {
            let cumulative_diff = provider.get_cumulative_difficulty_for_block_hash(base_block).await?;
            score += cumulative_diff;
            difficulty_map.insert(base_block.clone(), cumulative_diff);
        }
    }

    debug!("Cumulative difficulty for block {}: {} (from {} blue blocks)", 
        block_hash, score, blue_set.len());

    // save this result in cache
    cache.put((block_hash.clone(), base_block.clone(), base_block_height), (blue_set.clone(), score));

    Ok((blue_set, score))
}

// find the best tip (highest cumulative difficulty)
// We get their cumulative difficulty and sort them then take the first one
pub async fn find_best_tip<'a, P: DifficultyProvider + DagOrderProvider + CacheProvider>(provider: &P, tips: &'a HashSet<Hash>, base: &Hash, base_height: u64) -> Result<&'a Hash, BlockchainError> {
    if tips.len() == 0 {
        return Err(BlockchainError::ExpectedTips)
    }

    let mut scores = Vec::with_capacity(tips.len());
    for hash in tips {
        let block_tips = provider.get_past_blocks_for_block_hash(hash).await?;
        let (_, cumulative_difficulty) = find_tip_work_score(provider, hash, &block_tips, None, base, base_height).await?;
        scores.push((hash, cumulative_difficulty));
    }

    sort_descending_by_cumulative_difficulty(&mut scores);
    let (best_tip, _) = scores[0];
    Ok(best_tip)
}

// this function generate a DAG partial order into a full order using recursive calls.
// hash represents the best tip (biggest cumulative difficulty from GHOSTDAG blue set)
// base represents the block hash of a block already ordered and in stable height
// the full order is re generated each time a new block is added based on new TIPS
// first hash in order is the base hash
// base_height is only used for the cache key
//
// IMPORTANT: Uses GHOSTDAG k-cluster to filter blocks. Only BLUE blocks (honest, well-connected)
// are included in the ordering. RED blocks (anticone > k, potential attackers) are excluded.
// This ensures parasite chains are automatically excluded from the DAG ordering.
pub async fn generate_full_order<P>(provider: &P, hash: &Hash, base: &Hash, base_height: u64, base_topo_height: TopoHeight) -> Result<IndexSet<Hash>, BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider + CacheProvider
{
    trace!("generate full order for {} with base {}", hash, base);

    let chain_cache = provider.chain_cache().await;
    debug!("accessing full order cache for {} with base {}", hash, base);
    let mut cache = chain_cache.full_order_cache.lock().await;

    // Search in the cache first for the entire result
    let cache_key = (hash.clone(), base.clone(), base_height);
    if let Some(order_cache) = cache.get(&cache_key) {
        trace!("Full order for {} found in cache with {} blocks", hash, order_cache.len());
        return Ok(order_cache.clone());
    }

    // Calculate the blue set (GHOSTDAG k-cluster) for the best tip
    // This determines which blocks are "honest" and should be included in the ordering
    let tips = provider.get_past_blocks_for_block_hash(hash).await?;
    let blue_set = calculate_blue_set(provider, hash, &tips, base_topo_height).await?;
    
    debug!("Generating full order with blue set of {} blocks (k={})", blue_set.len(), GHOSTDAG_K);
    
    // Full order that is generated (only blue blocks)
    let mut full_order = IndexSet::new();
    // Current stack of hashes that need to be processed
    let mut stack: VecDeque<Hash> = VecDeque::new();
    stack.push_back(hash.clone());

    // Keep track of processed hashes that got reinjected for correct order
    let mut processed = IndexSet::new();

    'main: while let Some(current_hash) = stack.pop_back() {
        // If it is processed and got reinjected, its to maintains right order
        // We just need to insert current hash as it the "final hash" that got processed
        // after all tips
        if processed.contains(&current_hash) {
            full_order.insert(current_hash);
            continue 'main;
        }

        // Check if this block is in the blue set (honest blocks only)
        if !blue_set.contains(&current_hash) && current_hash != *base {
            trace!("Block {} is RED (anticone > k={}), excluding from full order", current_hash, GHOSTDAG_K);
            continue 'main;
        }

        // Retrieve block tips
        let block_tips = provider.get_past_blocks_for_block_hash(&current_hash).await?;

        // if the block is genesis or its the base block, we can add it to the full order
        if block_tips.is_empty() || current_hash == *base {
            full_order.insert(current_hash);
            continue 'main;
        }

        // Calculate the score for each tips above the base topoheight
        // Only consider tips that are in the blue set (honest blocks)
        let mut scores = Vec::new();
        for tip_hash in block_tips.iter() {
            // Skip red blocks (not in blue set)
            if !blue_set.contains(tip_hash) && *tip_hash != *base {
                trace!("Tip {} is RED, skipping in full order generation", tip_hash);
                continue;
            }

            let is_ordered = provider.is_block_topological_ordered(tip_hash).await?;
            if !is_ordered || provider.get_topo_height_for_hash(tip_hash).await? >= base_topo_height {
                let diff = provider.get_cumulative_difficulty_for_block_hash(tip_hash).await?;
                scores.push((tip_hash.clone(), diff));
            } else {
                trace!("Block {} is skipped in generate_full_order, is ordered = {}, base topo height = {}", tip_hash, is_ordered, base_topo_height);
            }
        }

        // We sort by ascending cumulative difficulty because it is faster
        // than doing a .reverse() on scores and give correct order for tips processing
        // using our stack impl
        sort_ascending_by_cumulative_difficulty(&mut scores);

        processed.insert(current_hash.clone());
        stack.push_back(current_hash);

        for (tip_hash, _) in scores {
            stack.push_back(tip_hash);
        }
    }

    debug!("Generated full order with {} blue blocks (excluded {} red blocks)", 
        full_order.len(), blue_set.len().saturating_sub(full_order.len()));

    cache.put(cache_key, full_order.clone());

    Ok(full_order)
}

// confirms whether the actual tip difficulty is withing 9% deviation with best tip (reference)
pub async fn validate_tips<P: DifficultyProvider>(provider: &P, best_tip: &Hash, tip: &Hash) -> Result<bool, BlockchainError> {
    const MAX_DEVIATION: Difficulty = Difficulty::from_u64(91);
    const PERCENTAGE: Difficulty = Difficulty::from_u64(100);

    let best_difficulty = provider.get_difficulty_for_block_hash(best_tip).await?;
    let block_difficulty = provider.get_difficulty_for_block_hash(tip).await?;

    Ok(best_difficulty * MAX_DEVIATION / PERCENTAGE < block_difficulty)
}