use std::{cmp::Ordering, collections::{HashMap, HashSet, VecDeque}};

use indexmap::IndexSet;
use itertools::Either;
use log::{debug, error, trace};
use xelis_common::{
    block::{BlockVersion, TopoHeight, get_combined_hash_for_tips}, crypto::Hash, difficulty::{CumulativeDifficulty, Difficulty}, time::TimestampMillis
};
use crate::{config::{STABLE_LIMIT, get_stable_limit}, core::storage::*};

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
pub async fn is_sync_block_at_height<P>(provider: &P, hash: &Hash, height: u64, block_version: BlockVersion) -> Result<bool, BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider + BlocksAtHeightProvider + PrunedTopoheightProvider
{
    trace!("is sync block {} at height {}", hash, height);
    let block_height = provider.get_height_for_block_hash(hash).await?;
    if block_height == 0 { // genesis block is a sync block
        trace!("Block {} at height {} is a sync block because it can only be the genesis block", hash, block_height);
        return Ok(true)
    }

    // block must be ordered and in stable height
    let stable_limit = get_stable_limit(block_version);
    if block_height + stable_limit > height || !provider.is_block_topological_ordered(hash).await? {
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

    // now lets check all blocks until STABLE_LIMIT height before the block
    let stable_point = if block_height >= STABLE_LIMIT {
        block_height - STABLE_LIMIT
    } else {
        STABLE_LIMIT - block_height
    };
    let mut i = block_height.saturating_sub(1);
    let mut pre_blocks = HashSet::new();
    while i >= stable_point && i != 0 {
        let blocks = provider.get_blocks_at_height(i).await?;
        pre_blocks.extend(blocks);
        i -= 1;
    }

    let sync_block_cumulative_difficulty = provider.get_cumulative_difficulty_for_block_hash(hash).await?;
    // if potential sync block has lower cumulative difficulty than one of past blocks, it is not a sync block
    for pre_hash in pre_blocks {
        // We compare only against block ordered otherwise we can have desync between node which could lead to fork
        // This is rare event but can happen
        if provider.is_block_topological_ordered(&pre_hash).await? {
            let cumulative_difficulty = provider.get_cumulative_difficulty_for_block_hash(&pre_hash).await?;
            if cumulative_difficulty >= sync_block_cumulative_difficulty {
                debug!("Block {} at height {} is not a sync block, it has lower cumulative difficulty than block {} at height {}", hash, block_height, pre_hash, i);
                return Ok(false)
            }
        }
    }

    trace!("block {} at height {} is a sync block", hash, block_height);

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

pub async fn find_tip_base<P>(provider: &P, hash: &Hash, height: u64, pruned_topoheight: TopoHeight, block_version: BlockVersion) -> Result<(Hash, u64), BlockchainError>
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
            if is_sync_block_at_height(provider, &tip_hash, height, block_version).await? {
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
pub async fn find_common_base<'a, P, I>(provider: &P, tips: I, block_version: BlockVersion) -> Result<(Hash, u64), BlockchainError>
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

    let pruned_topoheight = provider.get_pruned_topoheight().await?.unwrap_or(0);
    let mut bases = Vec::new();
    for hash in tips.into_iter() {
        trace!("Searching tip base for {}", hash);
        bases.push(find_tip_base(provider, hash, best_height, pruned_topoheight, block_version).await?);
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
pub async fn find_lowest_height_from_mainchain<P>(provider: &P, hash: Hash) -> Result<Option<u64>, BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider
{
    // Lowest height found from mainchain
    let mut lowest_height = None;
    // Current stack of blocks to process
    let mut stack: VecDeque<Hash> = VecDeque::new();
    // Because several blocks can have the same tips,
    // prevent to process a block twice
    let mut processed = HashSet::new();

    stack.push_back(hash);

    while let Some(current_hash) = stack.pop_back() {
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
                stack.push_back(tip_hash.clone());
            }
        }
        processed.insert(current_hash);
    }

    Ok(lowest_height)
}

// Search the lowest height available from this block hash
// This function is used to calculate the distance from mainchain
// It will recursively search all tips and their height
// If a tip is not ordered, we will search its tips until we find an ordered block
pub async fn calculate_distance_from_mainchain<P>(provider: &P, hash: &Hash) -> Result<Option<u64>, BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider
{
    if provider.is_block_topological_ordered(hash).await? {
        let height = provider.get_height_for_block_hash(hash).await?;
        debug!("calculate_distance: Block {} is at height {}", hash, height);
        return Ok(Some(height))
    }
    debug!("calculate_distance: Block {} is not ordered, calculate distance from mainchain", hash);
    let lowest_height = find_lowest_height_from_mainchain(provider, hash.clone()).await?;

    debug!("calculate_distance: lowest height found is {:?}", lowest_height);
    Ok(lowest_height)
}

// Verify if the block is not too far from mainchain
// We calculate the distance from mainchain and compare it to the height
pub async fn is_near_enough_from_main_chain<P>(provider: &P, hash: &Hash, chain_height: u64) -> Result<bool, BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider
{
    let Some(lowest_ordered_height) = calculate_distance_from_mainchain(provider, hash).await? else {
        return Ok(false);
    };

    debug!("distance for block {}: {} at chain height {}", hash, lowest_ordered_height, chain_height);

    // If the lowest ordered height is below or equal to current chain height
    // and that we have a difference bigger than our stable limit
    if lowest_ordered_height <= chain_height && chain_height - lowest_ordered_height >= STABLE_LIMIT {
        return Ok(false)
    }

    Ok(true)
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

// find the sum of work done
pub async fn find_tip_work_score<P>(
    provider: &P,
    block_hash: &Hash,
    block_tips: impl Iterator<Item = &Hash>,
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

    let mut map: HashMap<Hash, CumulativeDifficulty> = HashMap::new();
    let block_difficulty = if let Some(diff) = block_difficulty {
        diff
    } else {
        provider.get_difficulty_for_block_hash(&block_hash).await?
    };

    map.insert(block_hash.clone(), block_difficulty);

    // Lookup for each unique block difficulty in the past blocks 
    let base_topoheight = provider.get_topo_height_for_hash(base_block).await?;
    for hash in block_tips {
        if !map.contains_key(hash) {
            let is_ordered = provider.is_block_topological_ordered(hash).await?;
            if !is_ordered || provider.get_topo_height_for_hash(hash).await? >= base_topoheight {
                find_tip_work_score_internal(provider, &mut map, hash, base_topoheight).await?;
            }
        }
    }

    if base_block != block_hash {
        map.insert(base_block.clone(), provider.get_cumulative_difficulty_for_block_hash(base_block).await?);
    }

    let mut set = HashSet::with_capacity(map.len());
    let mut score = CumulativeDifficulty::zero();
    for (hash, value) in map {
        set.insert(hash);
        score += value;
    }

    // save this result in cache
    cache.put((block_hash.clone(), base_block.clone(), base_block_height), (set.clone(), score));

    Ok((set, score))
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
        let (_, cumulative_difficulty) = find_tip_work_score(provider, hash, block_tips.iter(), None, base, base_height).await?;
        scores.push((hash, cumulative_difficulty));
    }

    sort_descending_by_cumulative_difficulty(&mut scores);
    let (best_tip, _) = scores[0];
    Ok(best_tip)
}

// this function generate a DAG paritial order into a full order using recursive calls.
// hash represents the best tip (biggest cumulative difficulty)
// base represents the block hash of a block already ordered and in stable height
// the full order is re generated each time a new block is added based on new TIPS
// first hash in order is the base hash
// base_height is only used for the cache key
pub async fn generate_full_order<P>(provider: &P, hash: &Hash, base: &Hash, base_height: u64, base_topo_height: TopoHeight) -> Result<IndexSet<Hash>, BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider + CacheProvider
{
    trace!("generate full order for {} with base {}", hash, base);

    let chain_cache = provider.chain_cache().await;
    debug!("accessing full order cache for {} with base {}", hash, base);
    let mut cache = chain_cache.full_order_cache.lock().await;

    // Full order that is generated
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

        // Search in the cache to retrieve faster the full order
        let cache_key = (current_hash.clone(), base.clone(), base_height);
        if let Some(order_cache) = cache.get(&cache_key) {
            full_order.extend(order_cache.clone());
            continue 'main;
        }

        // Retrieve block tips
        let block_tips = provider.get_past_blocks_for_block_hash(&current_hash).await?;

        // if the block is genesis or its the base block, we can add it to the full order
        if block_tips.is_empty() || current_hash == *base {
            let mut order = IndexSet::new();
            order.insert(current_hash.clone());
            cache.put(cache_key, order.clone());
            full_order.extend(order);
            continue 'main;
        }

        // Calculate the score for each tips above the base topoheight
        let mut scores = Vec::new();
        for tip_hash in block_tips.iter() {
            let is_ordered = provider.is_block_topological_ordered(tip_hash).await?;
            if !is_ordered || provider.get_topo_height_for_hash(tip_hash).await? >= base_topo_height {
                let diff = provider.get_cumulative_difficulty_for_block_hash(tip_hash).await?;
                scores.push((tip_hash.clone(), diff));
            } else {
                debug!("Block {} is skipped in generate_full_order, is ordered = {}, base topo height = {}", tip_hash, is_ordered, base_topo_height);
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

    cache.put((hash.clone(), base.clone(), base_height), full_order.clone());

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