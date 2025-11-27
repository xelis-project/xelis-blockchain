use std::collections::{HashMap, HashSet, VecDeque};

use indexmap::IndexSet;
use log::{debug, trace};
use xelis_common::{
    block::TopoHeight,
    difficulty::{CumulativeDifficulty, Difficulty},
    crypto::Hash,
};
use crate::core::{
    error::BlockchainError,
    storage::*
};
use super::sort_ascending_by_cumulative_difficulty;

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
) -> Result<(HashSet<Hash>, CumulativeDifficulty), BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider + CacheProvider
{
    trace!("find tip work score for {} at base {}", block_hash, base_block);

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

    Ok((set, score))
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