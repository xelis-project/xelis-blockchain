use std::collections::{HashMap, HashSet, VecDeque};

use indexmap::IndexSet;
use log::{debug, trace};
use xelis_common::{
    block::TopoHeight,
    crypto::Hash,
    difficulty::{CumulativeDifficulty, Difficulty},
};
use crate::{
    config::GHOSTDAG_K,
    core::{
        storage::*,
        error::BlockchainError,
    },
};

use super::sort_ascending_by_cumulative_difficulty;

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
    let cache_key = (block_hash.clone(), base_topoheight);
    {
        let chain_cache = provider.chain_cache().await;
        let mut blue_set_cache = chain_cache.blue_set_cache.lock().await;
    
        // Check cache first
        if let Some(cached) = blue_set_cache.get(&cache_key) {
            debug!("Blue set for block {} found in cache ({} blocks)", block_hash, cached.len());
            return Ok(cached.clone());
        }
    }

    trace!("Calculating GHOSTDAG blue set for block {} with base topoheight {} and k={}", block_hash, base_topoheight, GHOSTDAG_K);

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

    {
        let chain_cache = provider.chain_cache().await;
        let mut blue_set_cache = chain_cache.blue_set_cache.lock().await;

        // Cache the result
        blue_set_cache.put(cache_key, blue_set.clone());
    }

    Ok(blue_set)
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
 
    // Add current block's difficulty
    score += block_difficulty;

    // Add difficulty only from blue blocks
    for hash in blue_set.iter() {
        if hash != block_hash {
            let diff = provider.get_difficulty_for_block_hash(hash).await?;
            score += diff;
        }
    }

    debug!("Cumulative difficulty for block {}: {} (from {} blue blocks)", block_hash, score, blue_set.len());

    // save this result in cache
    {
        let chain_cache = provider.chain_cache().await;
        let mut cache = chain_cache.tip_work_score_cache.lock().await;
        cache.put(cache_key, (blue_set.clone(), score));
    }

    Ok((blue_set, score))
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