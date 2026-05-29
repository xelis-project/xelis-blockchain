use std::collections::{HashSet, VecDeque};

use futures::{StreamExt, TryStreamExt, stream, future::ready};
use indexmap::IndexSet;
use linked_hash_table::{LinkedHashMap, LinkedHashSet};
use log::{debug, trace};
use xelis_common::{
    config::TIPS_LIMIT,
    crypto::Hash,
    difficulty::{CumulativeDifficulty, Difficulty},
};
use crate::core::{
    error::BlockchainError,
    storage::{
        ConcurrencyProvider,
        DifficultyProvider,
        DagOrderProvider,
        MergeSet,
        MergeSetProvider,
    }
};

/// The k parameter: maximum anticone size for a block to be blue
/// we expect at most k honest parallel blocks per interval
pub const K: usize = TIPS_LIMIT;

/// Result of coloring a blue candidate (Kaspa-style)
enum ColoringOutput {
    /// Block is blue: (candidate_anticone_size, affected_blues_anticone_sizes)
    /// The map contains the *current* anticone sizes of each blue block that
    /// is in the candidate's anticone (before the +1 increment applied by `add_blue`)
    Blue(usize, LinkedHashMap<Hash, usize>),
    /// Block is red (anticone exceeds k)
    Red,
}

/// Intermediate coloring state when walking one chain block.
enum ColoringState {
    /// Candidate is definitely blue (chain block is ancestor of candidate,
    /// so all remaining blues on the chain are in candidate's past)
    Blue,
    /// Candidate is definitely red (k-cluster violation)
    Red,
    /// Not yet determined (continue walking)
    Pending,
}

/// This computes the block's selected parent, mergeset, blue/red coloring and blue_work.
pub async fn compute_block_mergesets<P>(
    provider: &P,
    block_hash: &Hash,
    block_tips: &IndexSet<Hash>,
    block_difficulty: Difficulty,
) -> Result<(MergeSet, LinkedHashSet<Hash>, CumulativeDifficulty), BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider + MergeSetProvider + ConcurrencyProvider + Send + Sync,
{
    debug!("GHOSTDAG processing block {}", block_hash);

    let mut reds = LinkedHashSet::new();

    // Genesis special case: no tips, so no mergeset, and cumulative difficulty = block difficulty.
    let Some(selected_parent) = block_tips.first() else {
        // Genesis: cumulative difficulty = block_difficulty itself.
        return Ok((MergeSet::default(), reds, block_difficulty.into()));
    };

    // Step 1: Compute the mergeset
    let computed_mergeset = compute_mergeset(provider, block_tips, selected_parent).await?;

    // Step 2: Initialize the mergeset data structure with the selected parent as the first blue.
    let mut blues = MergeSet::new(selected_parent.clone());

    // Step 3: Color each mergeset block
    let computed_mergeset_len = computed_mergeset.len();
    for merge_block in computed_mergeset {
        let coloring = check_blue_candidate(
            provider,
            &blues,
            &merge_block,
            K,
        ).await?;

        match coloring {
            ColoringOutput::Blue(anticone_size, affected_sizes) => {
                blues.add_blue(merge_block, anticone_size, affected_sizes);
            }
            ColoringOutput::Red => {
                debug!("Block {} is red in the mergeset of {}", merge_block, block_hash);
                reds.insert(merge_block);
            }
        }
    }

    // Step 4: Compute blue work = cumulative difficulty.
    // blue_work = block_difficulty
    //           + selected_parent.cumulative_difficulty
    //           + sum(each mergeset blue's individual difficulty)
    // This value is what gets stored as the block's cumulative_difficulty.
    // Red blocks are excluded from blue_work.
    let selected_parent_cumulative_difficulty = provider
        .get_cumulative_difficulty_for_block_hash(selected_parent)
        .await?;

    // Skip the first entry (selected parent) because its difficulty is already
    // captured via selected_parent_cumulative_difficulty above.
    let blue_work = stream::iter(blues.keys().skip(1))
        .map(|blue_hash| provider.get_difficulty_for_block_hash(blue_hash))
        .buffered(provider.concurrency())
        .boxed()
        .try_fold(
            block_difficulty + selected_parent_cumulative_difficulty,
            |acc, diff| ready(Ok(acc + diff)),
        )
        .await?;

    debug!(
        "{}: blue_work={}, blues={}, reds={}, computed merge set={}",
        block_hash,
        blue_work,
        blues.len(),
        reds.len(),
        computed_mergeset_len,
    );

    Ok((blues, reds, blue_work))
}

pub async fn is_dag_ancestor_of<P>(
    provider: &P,
    ancestor: &Hash,
    descendant: &Hash,
) -> Result<bool, BlockchainError>
where
    P: DifficultyProvider + Send + Sync,
{
    trace!("Checking DAG ancestry: is {} an ancestor of {}?", ancestor, descendant);

    if ancestor == descendant {
        return Ok(true);
    }

    let ancestor_height = provider.get_height_for_block_hash(ancestor).await?;
    let descendant_height = provider.get_height_for_block_hash(descendant).await?;

    // Can't be the same height because block height is always highest tip height + 1
    if descendant_height <= ancestor_height {
        return Ok(false); // Can't be an ancestor if it's at or below the ancestor's height
    }

    let mut visited = HashSet::new();
    let mut stack = vec![descendant.clone()];
    while let Some(current) = stack.pop() {
        if !visited.insert(current.clone()) {
            continue; // Already visited
        }

        if current == *ancestor {
            return Ok(true);
        }

        let current_height = provider.get_height_for_block_hash(&current).await?;
        if current_height <= ancestor_height {
            continue; // Can't be an ancestor if it's at or below the ancestor's height
        }

        let parents = provider.get_past_blocks_for_block_hash(&current).await?;
        stack.extend(parents.iter().cloned());
    }

    Ok(false)
}

/// Compute the mergeset: blocks in the union of all tips' pasts that are NOT
/// in the selected parent's past.
///
/// GHOSTDAG requires processing merge-set candidates topologically. Since block
/// height is strictly monotonic along parent links in this codebase
/// (`height(parent) < height(child)`), sorting by height ascending provides a
/// valid topological order. For equal-height candidates (which are never
/// ancestor/descendant), we apply deterministic tie-breaks by cumulative
/// difficulty, then by hash, so the result does not depend on traversal order.
async fn compute_mergeset<P>(
    provider: &P,
    tips: &IndexSet<Hash>,
    selected_parent: &Hash,
) -> Result<impl Iterator<Item = Hash> + ExactSizeIterator, BlockchainError>
where
    P: DifficultyProvider + Send + Sync,
{
    let mut mergeset = Vec::new();
    let mut visited = HashSet::new();
    let mut queue: VecDeque<Hash> = VecDeque::new();

    // Start from all non-selected-parent tips
    for tip in tips {
        if tip != selected_parent && !visited.contains(tip) {
            queue.push_back(tip.clone());
            visited.insert(tip.clone());
        }
    }

    while let Some(current) = queue.pop_front() {
        // If this block is an ancestor of the selected parent, skip it
        // (it's already accounted for in the selected parent's blue set)
        if is_dag_ancestor_of(provider, &current, selected_parent).await? {
            continue;
        }

        let height = provider.get_height_for_block_hash(&current).await?;
        let cumulative_difficulty = provider.get_cumulative_difficulty_for_block_hash(&current).await?;
        mergeset.push((current.clone(), height, cumulative_difficulty));

        // Traverse parents
        let past_blocks = provider.get_past_blocks_for_block_hash(&current).await?;
        for parent in past_blocks.iter() {
            if !visited.contains(parent) {
                visited.insert(parent.clone());
                queue.push_back(parent.clone());
            }
        }
    }

    // Enforce ancestor-first processing order required by GHOSTDAG
    // Deterministic tie-breaks for equal-height (concurrent) blocks:
    // cumulative difficulty (asc), then hash (asc)
    mergeset.sort_by(|(hash_a, height_a, cd_a), (hash_b, height_b, cd_b)| {
        height_a
            .cmp(height_b)
            .then_with(|| cd_a.cmp(cd_b))
            .then_with(|| hash_a.cmp(hash_b))
    });

    Ok(mergeset
        .into_iter()
        .map(|(hash, _, _)| hash))
}

/// Check if a candidate block should be colored blue.
///
/// Walks the selected parent chain from the new block backwards (theoretically
/// to genesis) checking the candidate's anticone size against k. The walk
/// terminates early in O(1) when the chain block is an ancestor of the
/// candidate (DAG reachability fast-path), or when a k-violation is found.
async fn check_blue_candidate<P>(
    provider: &P,
    new_block_data: &MergeSet,
    candidate: &Hash,
    k: usize,
) -> Result<ColoringOutput, BlockchainError>
where
    P: DifficultyProvider + MergeSetProvider + ConcurrencyProvider + Send + Sync,
{
    // Quick check: the mergeset can have at most k blue blocks (not counting the SP).
    // mergeset_blues includes the SP as its first entry, so the total capacity is k+1.
    // If we already have k+1 entries (SP + k non-SP blues), any further candidate is red.
    if new_block_data.len() > k {
        return Ok(ColoringOutput::Red);
    }

    let mut candidate_blues_anticone_sizes: LinkedHashMap<Hash, usize> = LinkedHashMap::new();
    let mut candidate_blue_anticone_size: usize = 0;

    // Level 0: check the new block's current blue set.
    // The new block has no hash yet (it's being built), so we pass None.
    let state = check_blue_candidate_with_chain_block(
        provider,
        new_block_data,
        None, // new block has no stored hash
        new_block_data,
        candidate,
        &mut candidate_blues_anticone_sizes,
        &mut candidate_blue_anticone_size,
        k,
    ).await?;

    match state {
        ColoringState::Blue => {
            return Ok(ColoringOutput::Blue(candidate_blue_anticone_size, candidate_blues_anticone_sizes));
        }
        ColoringState::Red => return Ok(ColoringOutput::Red),
        ColoringState::Pending => {}
    }

    // Walk the selected parent chain
    // The selected parent is always the first key in mergeset_blues.
    let mut chain_block_hash = new_block_data.get_selected_parent().cloned();

    while let Some(hash) = chain_block_hash.take() {
        let chain_data = provider.get_mergeset(&hash).await?;

        let state = check_blue_candidate_with_chain_block(
            provider,
            new_block_data,
            Some(&hash),
            &chain_data,
            candidate,
            &mut candidate_blues_anticone_sizes,
            &mut candidate_blue_anticone_size,
            k,
        ).await?;

        match state {
            ColoringState::Blue => {
                return Ok(ColoringOutput::Blue(candidate_blue_anticone_size, candidate_blues_anticone_sizes));
            }
            ColoringState::Red => return Ok(ColoringOutput::Red),
            ColoringState::Pending => {}
        }

        // The SP of chain_data is its first mergeset_blues key.
        chain_block_hash = chain_data.take_selected_parent();
    }

    // Reached genesis without k-violation: BLUE
    Ok(ColoringOutput::Blue(candidate_blue_anticone_size, candidate_blues_anticone_sizes))
}

/// Check a blue candidate against one chain block's blue set.
///
/// Returns `Blue` for early termination (chain block is ancestor of candidate),
/// `Red` on k-violation, or `Pending` to continue walking.
///
/// This is the inner loop of Kaspa's `check_blue_candidate_with_chain_block`.
async fn check_blue_candidate_with_chain_block<P>(
    provider: &P,
    new_block_data: &MergeSet,
    chain_block_hash: Option<&Hash>,
    chain_block_data: &MergeSet,
    candidate: &Hash,
    candidate_blues_anticone_sizes: &mut LinkedHashMap<Hash, usize>,
    candidate_blue_anticone_size: &mut usize,
    k: usize,
) -> Result<ColoringState, BlockchainError>
where
    P: DifficultyProvider + MergeSetProvider + ConcurrencyProvider + Send + Sync,
{
    // If the chain block is a known block (not the new block being built),
    // check if it's an ancestor of the candidate.
    // If so, ALL remaining blues on the chain are also ancestors -> BLUE.
    if let Some(hash) = chain_block_hash {
        if is_dag_ancestor_of(provider, hash, candidate).await? {
            return Ok(ColoringState::Blue);
        }
    }

    // Iterate over the chain block's blue set (SP + mergeset blues).
    for peer in chain_block_data.keys() {
        // Skip if peer is an ancestor of candidate (peer ∈ past(candidate))
        if is_dag_ancestor_of(provider, peer, candidate).await? {
            continue;
        }

        // peer is in candidate's anticone — look up its current anticone size
        let peer_blue_anticone_size = blue_anticone_size(
            provider,
            peer,
            new_block_data,
        ).await?;

        candidate_blues_anticone_sizes.insert(peer.clone(), peer_blue_anticone_size);

        *candidate_blue_anticone_size += 1;
        if *candidate_blue_anticone_size > k {
            // k-cluster violation: candidate's blue anticone exceeded k
            return Ok(ColoringState::Red);
        }

        if peer_blue_anticone_size == k {
            // k-cluster violation: adding the candidate would push this peer's
            // blue anticone over k
            return Ok(ColoringState::Red);
        }

        debug_assert!(
            peer_blue_anticone_size <= k,
            "found blue anticone larger than k"
        );
    }

    Ok(ColoringState::Pending)
}

/// Get the blue anticone size of `block` from the perspective of `context`.
///
/// `mergeset_blues` now doubles as the anticone-size index, so we look up
/// `block` in `context.mergeset_blues` first, then walk the selected parent
/// chain (each stored GhostdagData's SP is its first `mergeset_blues` key)
/// until the block is found.
async fn blue_anticone_size<P>(
    provider: &P,
    block: &Hash,
    context: &MergeSet,
) -> Result<usize, BlockchainError>
where
    P: MergeSetProvider,
{
    // Check the context's own map first (most common case)
    if let Some(size) = context.get(block) {
        return Ok(size);
    }

    // Walk back the selected parent chain.
    // The SP of any block is always its first mergeset_blues key.
    let mut current_sp = context.get_selected_parent().cloned();
    while let Some(sp) = current_sp.take() {
        let sp_data = provider.get_mergeset(&sp).await?;
        if let Some(size) = sp_data.get(block) {
            return Ok(size);
        }

        current_sp = sp_data.take_selected_parent();
    }

    return Err(BlockchainError::Unknown)
}