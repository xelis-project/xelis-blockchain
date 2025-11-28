use std::{collections::{HashSet, VecDeque}, sync::Arc};

use indexmap::IndexSet;
use log::{debug, trace};
use lru::LruCache;
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

    let mut blue_set = HashSet::new();

    let chain_cache = provider.chain_cache().await;
    let mut ghost_dag_cache = chain_cache.ghost_dag_cache.lock().await;

    // Walk the selected parent chain and collect blues
    let mut current = Some((block_hash.clone(), block_tips.clone()));    
    while let Some((hash, tips)) = current.take() {
        // Check if above base
        if is_above_base(provider, &hash, base_topoheight).await? {
            blue_set.insert(hash.clone());
        } else {
            break; // Reached base, stop
        }

        // Get GHOSTDAG data for current block
        let data = get_or_compute_ghost_dag_data(&mut ghost_dag_cache, provider, &hash, &tips).await?;

        // Add merge set blues
        for blue in data.merge_set_blues.iter() {
            if is_above_base(provider, blue, base_topoheight).await? {
                blue_set.insert(blue.clone());
            }
        }
        
        // Move to selected parent
        current = match data.selected_parent.as_ref() {
            Some(sp) => {
                let tips = provider.get_past_blocks_for_block_hash(sp).await?;
                Some((sp.clone(), tips.into_owned()))
            }
            None => None,
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
    ghost_dag_cache: &mut LruCache<Hash, Arc<GhostDagData>>,
    provider: &P,
    hash: &Hash,
    tips: &IndexSet<Hash>
) -> Result<Arc<GhostDagData>, BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider + CacheProvider
{
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
        if ghost_dag_cache.contains(&block_hash) {
            continue;
        }
        
        // Get tips if needed
        let tips = if block_tips.is_empty() {
            provider.get_past_blocks_for_block_hash(&block_hash).await?.to_owned()
        } else {
            block_tips
        };
        
        needs_computation.push((block_hash, tips.clone()));
        
        // Add parents to queue
        for tip in tips.iter() {
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
            if ghost_dag_cache.contains(&block_hash) {
                computed_set.insert(block_hash);
                continue;
            }
            
            // Find which parent would be selected
            let selected_parent_opt = if !block_tips.is_empty() {
                let selected_parent = find_selected_parent_from_cache(ghost_dag_cache, provider, &block_tips).await?;
                Some(selected_parent)
            } else {
                None
            };
            
            // Check if selected parent is ready (or no parents)
            let can_compute = if let Some(sp) = &selected_parent_opt {
                computed_set.contains(sp) || ghost_dag_cache.contains(sp)
            } else {
                true // Genesis block
            };
            
            if can_compute {
                // Compute for this block
                let data = compute_ghost_dag_data_single(ghost_dag_cache, provider, &block_hash, &block_tips).await?;
                
                // Cache it
                ghost_dag_cache.put(block_hash.clone(), data);
                computed_set.insert(block_hash);
            } else {
                // Defer to next round
                next_round.push((block_hash, block_tips));
            }
        }
        
        remaining = next_round;
    }

    // Return from cache
    // TODO: fix this
    Box::pin(get_or_compute_ghost_dag_data(ghost_dag_cache, provider, hash, tips)).await
}

// Compute GHOSTDAG data for a single block (assumes parents are cached)
async fn compute_ghost_dag_data_single<P>(
    ghost_dag_cache: &mut LruCache<Hash, Arc<GhostDagData>>,
    provider: &P,
    _hash: &Hash,
    tips: &IndexSet<Hash>
) -> Result<Arc<GhostDagData>, BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider + CacheProvider
{
    // Genesis block
    if tips.is_empty() {
        // Genesis has zero cumulative difficulty (no parent difficulty to accumulate)
        return Ok(Arc::new(GhostDagData {
            cumulative_difficulty: CumulativeDifficulty::zero(),
            selected_parent: None,
            merge_set_blues: HashSet::new(),
        }));
    }

    // Find selected parent
    let selected_parent = find_selected_parent_from_cache(ghost_dag_cache, provider, tips).await?;
    
    // Get selected parent's data from cache
    // TODO: fix this
    let sp_data = Box::pin(get_or_compute_ghost_dag_data(ghost_dag_cache, provider, &selected_parent, &IndexSet::new())).await?;
    
    // Compute merge set and classify as blue/red
    let merge_set_blues = compute_merge_set_classification(
        ghost_dag_cache,
        provider,
        tips,
        &selected_parent,
        &sp_data
    ).await?;

    // cumulative_difficulty = sp_cumulative_difficulty + sp_difficulty + sum(blue_difficulties)
    let mut cumulative_difficulty = provider.get_cumulative_difficulty_for_block_hash(&selected_parent).await?;
    
    // Add selected parent's own difficulty (not cumulative, just the block's difficulty)
    let sp_difficulty = provider.get_difficulty_for_block_hash(&selected_parent).await?;
    cumulative_difficulty += sp_difficulty;

    // Add merge set blues' difficulties (not cumulative, just each block's difficulty)
    for blue_hash in merge_set_blues.iter() {
        let blue_diff = provider.get_difficulty_for_block_hash(blue_hash).await?;
        cumulative_difficulty += blue_diff;
    }

    Ok(Arc::new(GhostDagData {
        cumulative_difficulty,
        selected_parent: Some(selected_parent),
        merge_set_blues,
    }))
}

// Find selected parent from cache: highest cumulative difficulty
// Retrieves cumulative difficulty from cache if available, otherwise fetches cumulative difficulty from provider
async fn find_selected_parent_from_cache<P>(
    ghost_dag_cache: &mut LruCache<Hash, Arc<GhostDagData>>,
    provider: &P,
    tips: &IndexSet<Hash>
) -> Result<Hash, BlockchainError>
where
    P: DifficultyProvider
{
    // Collect all blue work scores with their tips
    let mut tips_with_work = Vec::with_capacity(tips.len());

    for tip in tips.iter() {
        let cumulative_difficulty = if let Some(data) = ghost_dag_cache.get(tip) {
            // Use cached
            data.cumulative_difficulty
        } else {
            // Fetch cumulative difficulty from provider
            provider.get_cumulative_difficulty_for_block_hash(tip).await?
        };
        tips_with_work.push((tip, cumulative_difficulty));
    }

    // Sort ascending by cumulative difficulty (highest work first), ties broken by hash
    sort_ascending_by_cumulative_difficulty(&mut tips_with_work);
    
    // Return the first (highest cumulative difficulty)
    tips_with_work.pop()
        .map(|(h, _)| h.clone())
        .ok_or(BlockchainError::Unknown)
}

// Compute and classify merge set
async fn compute_merge_set_classification<P>(
    ghost_dag_cache: &mut LruCache<Hash, Arc<GhostDagData>>,
    provider: &P,
    tips: &IndexSet<Hash>,
    selected_parent: &Hash,
    sp_data: &GhostDagData
) -> Result<HashSet<Hash>, BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider + CacheProvider
{
    let mut blues = HashSet::new();
    
    // Process non-selected-parent tips
    for tip in tips {
        if tip == selected_parent {
            continue;
        }
        
        // Check if this tip should be blue or red
        if is_blue_candidate(ghost_dag_cache, provider, tip, selected_parent, sp_data).await? {
            blues.insert(tip.clone());
        }
    }
    
    Ok(blues)
}

// Check if a candidate should be classified as blue
// by checking its anticone size relative to the SP chain
async fn is_blue_candidate<P>(
    ghost_dag_cache: &mut LruCache<Hash, Arc<GhostDagData>>,
    provider: &P,
    candidate: &Hash,
    selected_parent: &Hash,
    sp_data: &GhostDagData
) -> Result<bool, BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider + CacheProvider
{
    // Build candidate's reachability set (cache first, then provider)
    let candidate_reachable = build_reachability_set(ghost_dag_cache, provider, candidate).await?;

    let mut anticone_size = 0;
    let mut visited = HashSet::new();
    
    // Check SP and its merge set blues
    if !candidate_reachable.contains(selected_parent) {
        visited.insert(selected_parent.clone());
        anticone_size += 1;
        if anticone_size > GHOSTDAG_K {
            return Ok(false);
        }
    }
    
    for blue in sp_data.merge_set_blues.iter() {
        if !candidate_reachable.contains(blue) && visited.insert(blue.clone()) {
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
        
        if visited.insert(hash.clone()) {
            anticone_size += 1;
            if anticone_size > GHOSTDAG_K {
                return Ok(false);
            }
        }

        // We can pass an empty IndexSet, it will be lazily fetched if needed
        // TODO: no recursive!
        let data = Box::pin(get_or_compute_ghost_dag_data(ghost_dag_cache, provider, &hash, &IndexSet::new())).await?;
        
        for blue in data.merge_set_blues.iter() {
            if !candidate_reachable.contains(blue) && visited.insert(blue.clone()) {
                anticone_size += 1;
                if anticone_size > GHOSTDAG_K {
                    return Ok(false);
                }
            }
        }
        current = data.selected_parent.clone();
    }
    
    Ok(anticone_size <= GHOSTDAG_K)
}

// Build reachability set using GHOSTDAG cache first, then provider for parents
// Cache provides GHOSTDAG structure (selected parent + blues), provider gives raw parent list
async fn build_reachability_set<P>(
    ghost_dag_cache: &mut LruCache<Hash, Arc<GhostDagData>>,
    provider: &P,
    hash: &Hash
) -> Result<HashSet<Hash>, BlockchainError>
where
    P: DifficultyProvider
{
    let mut reachable = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(hash.clone());
    reachable.insert(hash.clone());
    
    while let Some(current) = queue.pop_front() {
        // Try cache first for GHOSTDAG structure
        if let Some(data) = ghost_dag_cache.get(&current).cloned() {
            // Use GHOSTDAG data: selected parent + merge set blues
            if let Some(sp) = &data.selected_parent {
                if reachable.insert(sp.clone()) {
                    queue.push_back(sp.clone());
                }
            }
            
            for blue in &data.merge_set_blues {
                if reachable.insert(blue.clone()) {
                    queue.push_back(blue.clone());
                }
            }
        } else {
            // Not in cache, get raw parent list from provider
            let parents = provider.get_past_blocks_for_block_hash(&current).await?;
            for parent in parents.iter() {
                if reachable.insert(parent.clone()) {
                    queue.push_back(parent.clone());
                }
            }
        }
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
) -> Result<(HashSet<Hash>, CumulativeDifficulty), BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider + CacheProvider
{
    trace!("find tip work score for {} at base {}", block_hash, base_block);
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