use std::{collections::{HashMap, HashSet, VecDeque}, sync::Arc};

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

// Calculate blue set by walking the pre-computed GHOSTDAG data
// This is fast because we just follow the selected parent chain
pub async fn calculate_blue_set<P>(
    provider: &P,
    block_hash: &Hash,
    block_tips: &IndexSet<Hash>,
    base_topoheight: TopoHeight
) -> Result<HashSet<Hash>, BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider + CacheProvider
{
    trace!("Calculating blue set for block {} from base topoheight {}", block_hash, base_topoheight);

    // Ensure this block has its GHOSTDAG data computed
    let _data = get_or_compute_ghost_dag_data(provider, block_hash, block_tips).await?;

    let mut blue_set = HashSet::new();
    
    // Walk the selected parent chain and collect blues
    let mut current = Some(block_hash.clone());
    let chain_cache = provider.chain_cache().await;
    
    while let Some(hash) = current {
        // Check if above base
        if is_above_base(provider, &hash, base_topoheight).await? {
            blue_set.insert(hash.clone());
        } else {
            break; // Reached base, stop
        }
        
        // Get GHOSTDAG data for current block
        let data = {
            let cache = chain_cache.ghost_dag_cache.lock().await;
            cache.get(&hash).cloned()
        };
        
        if let Some(d) = data {
            // Add merge set blues
            for blue in &d.merge_set_blues {
                if is_above_base(provider, blue, base_topoheight).await? {
                    blue_set.insert(blue.clone());
                }
            }
            
            // Move to selected parent
            current = d.selected_parent.clone();
        } else {
            // No GHOSTDAG data - block might be orphaned or not yet computed
            // Try to compute it
            if let Ok(data) = get_or_compute_ghost_dag_data(provider, &hash, &IndexSet::new()).await {
                for blue in &data.merge_set_blues {
                    if is_above_base(provider, blue, base_topoheight).await? {
                        blue_set.insert(blue.clone());
                    }
                }
                current = data.selected_parent.clone();
            } else {
                break;
            }
        }
    }

    debug!("Blue set for {} contains {} blocks", block_hash, blue_set.len());
    Ok(blue_set)
}

#[inline]
async fn is_above_base<P>(provider: &P, hash: &Hash, base: TopoHeight) -> Result<bool, BlockchainError>
where P: DagOrderProvider
{
    if provider.is_block_topological_ordered(hash).await? {
        Ok(provider.get_topo_height_for_hash(hash).await? >= base)
    } else {
        Ok(true) // Not yet ordered, consider it above base
    }
}

// Get or compute GHOSTDAG data for a block (FULLY ITERATIVE)
// This is computed ONCE when the block is added and cached forever
pub async fn get_or_compute_ghost_dag_data<P>(
    provider: &P,
    hash: &Hash,
    tips: &IndexSet<Hash>
) -> Result<Arc<GhostDagData>, BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider + CacheProvider
{
    let chain_cache = provider.chain_cache().await;
    let mut ghost_dag_cache = chain_cache.ghost_dag_cache.lock().await;
    
    // Check cache first
    if let Some(data) = ghost_dag_cache.get(hash) {
        return Ok(data.clone());
    }

    // BFS to collect blocks that need computation
    let mut needs_computation = Vec::new();
    let mut queue = VecDeque::new();
    let mut visited = HashSet::new();
    
    queue.push_back((hash.clone(), tips.clone()));
    visited.insert(hash.clone());
    
    while let Some((block_hash, block_tips)) = queue.pop_front() {
        // Check if cached
        if ghost_dag_cache.contains_key(&block_hash) {
            continue;
        }
        
        // Get tips if needed
        let tips = if block_tips.is_empty() {
            provider.get_past_blocks_for_block_hash(&block_hash).await?.iter().cloned().collect()
        } else {
            block_tips
        };
        
        needs_computation.push((block_hash, tips.clone()));
        
        // Add parents to queue
        for tip in &tips {
            if visited.insert(tip.clone()) {
                queue.push_back((tip.clone(), IndexSet::new()));
            }
        }
    }
    
    // Process blocks in multiple rounds until all are computed
    // In each round, we can compute blocks whose selected parent is already cached
    let mut computed_set = HashSet::new();
    let mut remaining = needs_computation;
    
    while !remaining.is_empty() {
        let mut next_round = Vec::new();
        
        for (block_hash, block_tips) in remaining {
            // Check if already computed by another thread
            if ghost_dag_cache.contains_key(&block_hash) {
                computed_set.insert(block_hash);
                continue;
            }
            
            // Find which parent would be selected
            let selected_parent_opt = if !block_tips.is_empty() {
                let selected_parent = find_selected_parent_from_cache(&ghost_dag_cache, &block_tips)?;
                Some(selected_parent)
            } else {
                None
            };
            
            // Check if selected parent is ready (or no parents)
            let can_compute = if let Some(sp) = &selected_parent_opt {
                computed_set.contains(sp) || ghost_dag_cache.contains_key(sp)
            } else {
                true // Genesis block
            };
            
            if can_compute {
                // Compute for this block
                let data = compute_ghost_dag_data_single(&ghost_dag_cache, provider, &block_hash, &block_tips).await?;
                
                // Cache it
                ghost_dag_cache.insert(block_hash.clone(), data);
                computed_set.insert(block_hash);
            } else {
                // Defer to next round
                next_round.push((block_hash, block_tips));
            }
        }
        
        remaining = next_round;
    }
    
    // Return from cache
    ghost_dag_cache.get(hash).cloned()
        .ok_or(BlockchainError::Unknown)
}

// Compute GHOSTDAG data for a single block (assumes parents are cached)
async fn compute_ghost_dag_data_single<P>(
    ghost_dag_cache: &HashMap<Hash, Arc<GhostDagData>>,
    provider: &P,
    _hash: &Hash,
    tips: &IndexSet<Hash>
) -> Result<Arc<GhostDagData>, BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider + CacheProvider
{
    // Genesis block
    if tips.is_empty() {
        return Ok(Arc::new(GhostDagData {
            blue_score: 1,
            selected_parent: None,
            merge_set_blues: HashSet::new(),
            merge_set_reds: HashSet::new(),
        }));
    }

    // Find selected parent
    let selected_parent = find_selected_parent_from_cache(ghost_dag_cache, tips)?;
    
    // Get selected parent's data from cache
    let sp_data = ghost_dag_cache.get(&selected_parent).cloned()
        .ok_or(BlockchainError::Unknown)?;
    
    // Compute merge set and classify as blue/red
    let (merge_set_blues, merge_set_reds) = compute_merge_set_classification(
        ghost_dag_cache,
        provider,
        tips,
        &selected_parent,
        &sp_data
    ).await?;

    let blue_score = sp_data.blue_score + 1 + merge_set_blues.len() as u64;

    Ok(Arc::new(GhostDagData {
        blue_score,
        selected_parent: Some(selected_parent),
        merge_set_blues,
        merge_set_reds,
    }))
}

// Find selected parent from cache: highest blue_score, then cumulative difficulty, then hash
// Uses blue_score=0 for uncached parents
fn find_selected_parent_from_cache(
    ghost_dag_cache: &HashMap<Hash, Arc<GhostDagData>>,
    tips: &IndexSet<Hash>
) -> Result<Hash, BlockchainError> {
    // Collect all blue scores with their tips
    let tips_with_scores: Vec<(Hash, u64)> = tips.iter()
        .map(|tip| (tip.clone(), ghost_dag_cache.get(tip).map(|d| d.blue_score).unwrap_or(0)))
        .collect();
    
    // Find highest blue score
    let max_score = tips_with_scores.iter().map(|(_, s)| *s).max().unwrap_or(0);
    
    // Among tips with max score, select by hash (deterministic)
    tips_with_scores.iter()
        .filter(|(_, score)| *score == max_score)
        .min_by_key(|(hash, _)| hash)
        .map(|(h, _)| h.clone())
        .ok_or(BlockchainError::Unknown)
}

// Compute and classify merge set
async fn compute_merge_set_classification<P>(
    ghost_dag_cache: &HashMap<Hash, Arc<GhostDagData>>,
    provider: &P,
    tips: &IndexSet<Hash>,
    selected_parent: &Hash,
    sp_data: &GhostDagData
) -> Result<(HashSet<Hash>, HashSet<Hash>), BlockchainError>
where
    P: DifficultyProvider + CacheProvider
{
    let mut blues = HashSet::new();
    let mut reds = HashSet::new();
    
    // Process non-selected-parent tips
    for tip in tips {
        if tip == selected_parent {
            continue;
        }
        
        // Check if this tip should be blue or red
        if is_blue_candidate(ghost_dag_cache, provider, tip, selected_parent, sp_data).await? {
            blues.insert(tip.clone());
        } else {
            reds.insert(tip.clone());
        }
    }
    
    Ok((blues, reds))
}

// Check if a candidate should be classified as blue
// by checking its anticone size relative to the SP chain
async fn is_blue_candidate<P>(
    ghost_dag_cache: &HashMap<Hash, Arc<GhostDagData>>,
    provider: &P,
    candidate: &Hash,
    selected_parent: &Hash,
    sp_data: &GhostDagData
) -> Result<bool, BlockchainError>
where
    P: DifficultyProvider + CacheProvider
{
    // Build candidate's reachability set (bounded)
    let candidate_reachable = build_reachability_set(provider, candidate, 2 * GHOSTDAG_K + 5).await?;
    
    let mut anticone_size = 0;
    
    // Check SP and its merge set blues
    if !candidate_reachable.contains(selected_parent) {
        anticone_size += 1;
        if anticone_size > GHOSTDAG_K {
            return Ok(false);
        }
    }
    
    for blue in &sp_data.merge_set_blues {
        if !candidate_reachable.contains(blue) {
            anticone_size += 1;
            if anticone_size > GHOSTDAG_K {
                return Ok(false);
            }
        }
    }
    
    // Walk SP chain
    let mut current = sp_data.selected_parent.clone();
    
    while let Some(hash) = current {
        if candidate_reachable.contains(&hash) {
            break; // Found common ancestor
        }
        
        anticone_size += 1;
        if anticone_size > GHOSTDAG_K {
            return Ok(false);
        }
        
        let data = ghost_dag_cache.get(&hash).cloned();
        
        if let Some(d) = data {
            for blue in &d.merge_set_blues {
                if !candidate_reachable.contains(blue) {
                    anticone_size += 1;
                    if anticone_size > GHOSTDAG_K {
                        return Ok(false);
                    }
                }
            }
            current = d.selected_parent.clone();
        } else {
            break;
        }
    }
    
    Ok(anticone_size <= GHOSTDAG_K)
}

// Build reachability set for a block (bounded BFS)
async fn build_reachability_set<P>(
    provider: &P,
    hash: &Hash,
    max_depth: usize
) -> Result<HashSet<Hash>, BlockchainError>
where
    P: DifficultyProvider
{
    let mut reachable = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(hash.clone());
    reachable.insert(hash.clone());
    
    let mut depth = 0;
    while let Some(current) = queue.pop_front() {
        if depth >= max_depth {
            break;
        }
        
        let tips = provider.get_past_blocks_for_block_hash(&current).await?;
        for tip in tips.iter() {
            if reachable.insert(tip.clone()) {
                queue.push_back(tip.clone());
            }
        }
        depth += 1;
    }
    
    Ok(reachable)
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