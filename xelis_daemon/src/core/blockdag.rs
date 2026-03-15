use std::{cmp::Ordering, collections::{HashMap, HashSet, VecDeque}, sync::Arc};

use linked_hash_table::LinkedHashSet;
use indexmap::{IndexMap, IndexSet};
use itertools::Either;
use log::{debug, error, trace};
use futures::{StreamExt, TryStreamExt, stream};
use xelis_common::{
    block::{BlockVersion, TopoHeight, get_combined_hash_for_tips},
    crypto::Hash,
    difficulty::{CumulativeDifficulty, Difficulty},
    time::TimestampMillis,
};
use crate::{config::get_stable_limit, core::storage::*};

use super::{    
    storage::DifficultyProvider,
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
pub async fn sort_tips<D, I, H>(provider: &D, tips: I) -> Result<impl Iterator<Item = H> + ExactSizeIterator, BlockchainError>
where
    D: DifficultyProvider + ConcurrencyProvider,
    I: Iterator<Item = H> + ExactSizeIterator + Send + Sync,
    H: AsRef<Hash> + Send + Sync,
{
    trace!("sort tips");
    let tips_len = tips.len();
    match tips_len {
        0 => Err(BlockchainError::ExpectedTips),
        1 => Ok(Either::Left(tips)),
        _ => {
            let mut scores = stream::iter(tips)
                .map(|hash| async move {
                    provider.get_cumulative_difficulty_for_block_hash(hash.as_ref()).await
                        .map(|cd| (hash, cd))
                })
                .buffer_unordered(provider.concurrency())
                .boxed()
                .try_collect::<Vec<_>>().await?;

            sort_descending_by_cumulative_difficulty(&mut scores);
            Ok(Either::Right(scores.into_iter().map(|(hash, _)| hash)))
        }
    }
}

// determine he lowest height possible based on tips and do N+1
pub async fn calculate_height_at_tips<'a, D, I>(provider: &D, tips: I) -> Result<u64, BlockchainError>
where
    D: DifficultyProvider + ConcurrencyProvider,
    I: Iterator<Item = &'a Hash> + ExactSizeIterator + Send + Sync
{
    trace!("calculate height at tips");
    let tips_len = tips.len();
    let mut height = stream::iter(tips)
        .map(|hash| provider.get_height_for_block_hash(hash))
        .buffer_unordered(provider.concurrency())
        .boxed()
        .try_fold(0, |current_height, tip_height| async move {
            Ok::<_, BlockchainError>(current_height.max(tip_height))
        }).await?;

    if tips_len != 0 {
        height += 1;
    }
    Ok(height)
}

// find the best tip based on cumulative difficulty of the blocks
pub async fn find_best_tip_by_cumulative_difficulty<'a, D, I, H>(provider: &D, tips: I) -> Result<H, BlockchainError>
where
    D: DifficultyProvider + ConcurrencyProvider,
    I: Iterator<Item = H> + ExactSizeIterator + Send + Sync,
    H: AsRef<Hash> + Send + Sync,
{
    trace!("find best tip by cumulative difficulty");
    sort_tips(provider, tips).await?
        .next()
        .ok_or(BlockchainError::ExpectedTips)
}

// Find the newest tip based on the timestamp of the blocks
pub async fn find_newest_tip_by_timestamp<'a, D, I>(provider: &D, tips: I) -> Result<(&'a Hash, TimestampMillis), BlockchainError>
where
    D: DifficultyProvider + ConcurrencyProvider,
    I: Iterator<Item = &'a Hash> + ExactSizeIterator + Send + Sync
{
    trace!("find newest tip by timestamp");
    let tips_len = tips.len();
    match tips_len {
        0 => Err(BlockchainError::ExpectedTips),
        _ => {
            let newest_tip = stream::iter(tips)
                .map(|hash| async move {
                    provider.get_timestamp_for_block_hash(hash).await
                        .map(|timestamp| (hash, timestamp))
                })
                .buffer_unordered(provider.concurrency())
                .boxed()
                .try_fold(None, |newest, (hash, timestamp)| async move {
                    Ok::<_, BlockchainError>(Some(match newest {
                        None => (hash, timestamp),
                        Some((_, newest_timestamp)) if timestamp > newest_timestamp => (hash, timestamp),
                        Some(current_newest) => current_newest,
                    }))
                }).await?;

            newest_tip.ok_or(BlockchainError::ExpectedTips)
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

    // Starting V6, we don't check the cumulative difficulty of previous blocks anymore
    if block_version < BlockVersion::V6 {
        // now lets check all blocks until STABLE_LIMIT height before the block
        let sync_cumulative_difficulty = provider.get_cumulative_difficulty_for_block_hash(hash).await?;

        let stable_limit = get_stable_limit(block_version);
        let stable_point = if block_height >= stable_limit {
            block_height - stable_limit
        } else {
            stable_limit - block_height
        };
        let mut i = block_height.saturating_sub(1);
        while i >= stable_point && i != 0 {
            let blocks_at_height = provider.get_blocks_at_height(i).await?;
            for pre in blocks_at_height {
                // compare only with ordered blocks
                if provider.is_block_topological_ordered(&pre).await? {
                    let cd = provider.get_cumulative_difficulty_for_block_hash(&pre).await?;
                    if cd >= sync_cumulative_difficulty {
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
    }

    trace!("block {} at height {} is a sync block", hash, block_height);

    Ok(true)
}

// Check if the block is a side block
// This is only used to determine the block reward
pub async fn is_side_block_internal<P>(provider: &P, hash: &Hash, block_topoheight: Option<u64>, current_topoheight: TopoHeight, block_version: BlockVersion) -> Result<bool, BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider + BlocksAtHeightProvider
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

    if block_version >= BlockVersion::V4 {
        // Check if we have a block at same height with a topoheight lower than this block
        let blocks_at_height = provider.get_blocks_at_height(height).await?;
        for block_hash in blocks_at_height {
            if block_hash != *hash && provider.is_block_topological_ordered(&block_hash).await? {
                let block_topo = provider.get_topo_height_for_hash(&block_hash).await?;
                if block_topo < topoheight {
                    debug!("Block {} is a side block at height {} because block {} has lower topoheight {}", hash, height, block_hash, block_topo);
                    return Ok(true)
                }
            }
        }
    } else {
        // verify if there is a block with height higher than this block in past N topo blocks
        let mut counter = 0;
        let mut i = topoheight - 1;
        let stable_limit = get_stable_limit(block_version);
        while counter < stable_limit && i > 0 {
            let hash_at_topo = provider.get_hash_at_topo_height(i).await?;
            let previous_height = provider.get_height_for_block_hash(&hash_at_topo).await?;
    
            if height <= previous_height {
                debug!("Block {} is a side block at height {} because block {} at topoheight {} has height {}", hash, height, hash_at_topo, i, previous_height);
                return Ok(true)
            }
            counter += 1;
            i -= 1;
        }
    }

    Ok(false)
}

pub async fn find_tip_base<P>(provider: &P, hash: &Hash, best_height: u64, pruned_topoheight: TopoHeight, block_version: BlockVersion) -> Result<(Hash, u64), BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider + BlocksAtHeightProvider + PrunedTopoheightProvider + CacheProvider
{
    debug!("find tip base for {} at height {}", hash, best_height);
    let chain_cache = provider.chain_cache().await;

    let mut stack: VecDeque<Hash> = VecDeque::new();
    stack.push_back(hash.clone());

    let mut bases: IndexMap<Hash, u64> = IndexMap::new();
    let mut processed = HashSet::new();

    'main: while let Some(current_hash) = stack.pop_back() {
        trace!("Finding tip base for {} at height {}", current_hash, best_height);
        processed.insert(current_hash.clone());
        if pruned_topoheight > 0 && provider.is_block_topological_ordered(&current_hash).await? {
            let topoheight = provider.get_topo_height_for_hash(&current_hash).await?;
            // Node is pruned, we only prune chain to stable height / sync block so we can return the hash
            if topoheight <= pruned_topoheight {
                let block_height = provider.get_height_for_block_hash(&current_hash).await?;
                debug!("Node is pruned, returns tip {} at {} as stable tip base", current_hash, block_height);
                bases.insert(current_hash.clone(), block_height);
                continue 'main;
            }
        }

        // first, check if we have it in cache
        {
            let mut cache = chain_cache.tip_base_cache.lock().await;
            if let Some((base_hash, base_height)) = cache.get(&(current_hash.clone(), best_height)).cloned() {
                trace!("Tip Base for {} at height {} found in cache: {} for height {}", current_hash, best_height, base_hash, base_height);
                bases.insert(base_hash, base_height);
                continue 'main;
            }
        }

        let tips = provider.get_past_blocks_for_block_hash(&current_hash).await?;
        let tips_count = tips.len();
        if tips_count == 0 { // only genesis block can have 0 tips saved
            bases.insert(current_hash.clone(), 0);
            continue 'main;
        }

        for tip_hash in tips.iter() {
            if pruned_topoheight > 0 && provider.is_block_topological_ordered(&tip_hash).await? {
                let topoheight = provider.get_topo_height_for_hash(&tip_hash).await?;
                // Node is pruned, we only prune chain to stable height / sync block so we can return the hash
                if topoheight <= pruned_topoheight {
                    let block_height = provider.get_height_for_block_hash(&tip_hash).await?;
                    debug!("Node is pruned, returns tip {} at {} as stable tip base", tip_hash, block_height);
                    bases.insert(tip_hash.clone(), block_height);
                    continue 'main;
                }
            }

            // if block is sync, it is a tip base
            if is_sync_block_at_height(provider, &tip_hash, best_height, block_version).await? {
                let block_height = provider.get_height_for_block_hash(&tip_hash).await?;
                // save in cache
                {
                    let mut cache = chain_cache.tip_base_cache.lock().await;
                    cache.put((hash.clone(), best_height), (tip_hash.clone(), block_height));
                }

                bases.insert(tip_hash.clone(), block_height);
                continue 'main;
            }

            if !processed.contains(tip_hash) {
                // Tip was not sync, we need to find its tip base too
                stack.push_back(tip_hash.clone());
            }
        }
    }

    if bases.is_empty() {
        error!("Tip base for {} at height {} not found", hash, best_height);
        return Err(BlockchainError::ExpectedTips)
    }

    // now we sort descending by height and return the last element
    bases.sort_by(|_, a, _, b| b.cmp(a));
    debug_assert!(bases[0] >= bases[bases.len() - 1]);

    let (base_hash, base_height) = bases.pop()
        .ok_or(BlockchainError::ExpectedTips)?;

    // save in cache
    {
        let mut cache = chain_cache.tip_base_cache.lock().await;
        cache.put((hash.clone(), best_height), (base_hash.clone(), base_height));
    }

    trace!("Tip Base for {} at height {} found: {} for height {}", hash, best_height, base_hash, base_height);

    Ok((base_hash, base_height))
}

pub async fn find_common_base_height<'a, P>(provider: &P, tips: &IndexSet<Hash>, block_version: BlockVersion) -> Result<u64, BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider + BlocksAtHeightProvider + PrunedTopoheightProvider + CacheProvider + ConcurrencyProvider,
{
    // Only genesis block can have 0 tips
    if tips.len() == 0 {
        return Ok(0)
    }

    let (_, base_height) = find_common_base(provider, tips, block_version).await?;
    Ok(base_height)
}

// find the common base (block hash and block height) of all tips
pub async fn find_common_base<'a, P, I>(provider: &P, tips: I, block_version: BlockVersion) -> Result<(Hash, u64), BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider + BlocksAtHeightProvider + PrunedTopoheightProvider + CacheProvider + ConcurrencyProvider,
    I: IntoIterator<Item = &'a Hash> + Clone + Send + Sync,
    I::IntoIter: ExactSizeIterator + Send + Sync
{
    debug!("find common base for tips {}", tips.clone().into_iter().map(|h| h.to_string()).collect::<Vec<String>>().join(", "));
    let chain_cache = provider.chain_cache().await;

    let combined_tips = get_combined_hash_for_tips(tips.clone().into_iter());
    {
        debug!("accessing common base cache");
        let mut cache = chain_cache.common_base_cache.lock().await;
        debug!("common base cache locked");

        if let Some((hash, height)) = cache.get(&combined_tips) {
            debug!("Common base found in cache: {} at height {}", hash, height);
            return Ok((hash.clone(), *height))
        }
    }

    let best_height = stream::iter(tips.clone().into_iter())
        .map(|hash| provider.get_height_for_block_hash(hash))
        .buffer_unordered(provider.concurrency())
        .boxed()
        .try_fold(None, |current_height, tip_height| async move {
            match (current_height, tip_height) {
                (None, tip_height) => Ok(Some(tip_height)),
                (Some(current), tip_height) if tip_height > current => Ok(Some(tip_height)),
                (current, _) => Ok(current),
            }
        }).await?
        .ok_or(BlockchainError::ExpectedTips)?;

    let pruned_topoheight = provider.get_pruned_topoheight().await?.unwrap_or(0);

    let mut bases = stream::iter(tips.into_iter())
        .map(|hash| find_tip_base(provider, hash, best_height, pruned_topoheight, block_version))
        .buffer_unordered(provider.concurrency())
        .boxed()
        .try_collect::<Vec<_>>().await?;

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
    {
        debug!("accessing common base cache to save common base");
        let mut cache = chain_cache.common_base_cache.lock().await;
        debug!("common base cache locked for write");
        cache.put(combined_tips, (base_hash.clone(), base_height));
    }

    Ok((base_hash, base_height))
}

/// Find the nearest topoheight from all tips
/// We keep iterating until a block is ordered and its the highest topoheight
/// It also return a LinkedHashSet of all the tips that are not ordered until the said topoheight
pub async fn find_nearest_topoheight<P, I>(provider: &P, tips: I) -> Result<TopoHeight, BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider,
    I: IntoIterator<Item = Hash> + Send + Sync,
{
    trace!("find nearest topoheight for tips");
    let mut stack = VecDeque::new();
    stack.extend(tips.into_iter());

    while let Some(current) = stack.pop_front() {
        if provider.is_block_topological_ordered(&current).await? {
            return provider.get_topo_height_for_hash(&current).await
        }

        let past_blocks = provider.get_past_blocks_for_block_hash(&current).await?;
        stack.extend(past_blocks.iter().cloned());
    }

    Err(BlockchainError::ExpectedTips)
}

/// Check if the transaction is executed in a block with topoheight lower or equal to the given topoheight
pub async fn is_tx_executed_for_topoheight<P>(provider: &P, tx_hash: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError>
where
    P: DagOrderProvider + ClientProtocolProvider,
{
    if provider.is_tx_executed_in_a_block(tx_hash).await? {
        debug!("TX {} from parent is executed, verifying its DAG relation", tx_hash);
        let executor = provider.get_block_executor_for_tx(tx_hash).await?;
        let executor_topoheight = provider.get_topo_height_for_hash(&executor).await?;
        // This means its not part of the DAG of the current block being verified, we don't skip it
        Ok(executor_topoheight <= topoheight)
    } else {
        Ok(false)
    }
}

/// Find the nearest base topoheight (ordered block) with main chain
/// All tips will join at the said base hash.
/// This function traces back from each tip to find the first ordered block (main chain) that is reachable.
/// Then it returns the ordered block with the highest height/topoheight (nearest to tips) among those reachable from all tips.
pub async fn find_nearest_base_topoheight<P, I>(provider: &P, tips: I, stable_height: u64) -> Result<TopoHeight, BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider,
    I: IntoIterator<Item = Hash> + ExactSizeIterator + Send + Sync,
{
    trace!("find nearest base with main chain for tips");

    let tips_len = tips.len();
    // Find ordered bases reachable from each tip
    let mut stack = VecDeque::new();
    stack.extend(tips.into_iter().map(|tip| (Arc::new(tip.clone()), tip)));
    let mut bases_per_topoheight: HashMap<TopoHeight, HashSet<Arc<Hash>>> = HashMap::new();

    while let Some((tip, current)) = stack.pop_front() {
        let height = provider.get_height_for_block_hash(&current).await?;
        if height < stable_height {
            // Skip blocks below stable height
            continue;
        }

        let past_blocks = provider.get_past_blocks_for_block_hash(&current).await?;

        // if there is no tips, it is the genesis block, we consider it as a base candidate
        if past_blocks.is_empty() || provider.is_block_topological_ordered(&current).await? {
            debug!("found ordered block {} at height {} while tracing back from tip {}, checking if it's a common base candidate", current, height, current);
            // Found an ordered block (on main chain)
            let topoheight = provider.get_topo_height_for_hash(&current).await?;

            let bases = bases_per_topoheight.entry(topoheight)
                .or_default();

            if bases.insert(tip.clone()) && bases.len() == tips_len {
                // If this is the first time we see this tip for this topoheight and that we have all tips in this topoheight, we can stop searching
                debug!("Found nearest base with main chain at topoheight {} for hash {} with all tips reachable", topoheight, current);
                return Ok(topoheight);
            }
        }

        stack.extend(past_blocks.iter().cloned().map(|past| (tip.clone(), past)));
    }

    Err(BlockchainError::ExpectedTips)
}

pub async fn build_reachability<P: DifficultyProvider>(provider: &P, hash: Hash, block_version: BlockVersion) -> Result<HashSet<Hash>, BlockchainError> {
    let mut set = HashSet::new();
    let mut stack: VecDeque<(Hash, u64)> = VecDeque::new();
    stack.push_back((hash, 0));

    let stable_limit = get_stable_limit(block_version);
    while let Some((current_hash, current_level)) = stack.pop_back() {
        if current_level >= 2 * stable_limit {
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
pub async fn verify_non_reachability<P>(provider: &P, tips: &IndexSet<Hash>, block_version: BlockVersion) -> Result<bool, BlockchainError>
    where P: ConcurrencyProvider + DifficultyProvider
{
    trace!("Verifying non reachability for block");
    let tips_count = tips.len();
    let reach = stream::iter(tips.iter())
        .map(|hash| build_reachability(provider, hash.clone(), block_version))
        .buffered(provider.concurrency())
        .boxed()
        .try_collect::<Vec<_>>().await?;

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
    P: DifficultyProvider + DagOrderProvider + ConcurrencyProvider
{
    // Lowest height found from mainchain
    let mut lowest_height = None;
    // Current stack of blocks to process
    let mut stack: VecDeque<Hash> = VecDeque::new();
    // Because several blocks can have the same tips,
    // prevent to process a block twice
    let mut processed = HashSet::new();

    stack.push_back(hash);

    enum Helper {
        Height(u64),
        Next(Hash),
    }

    while let Some(current_hash) = stack.pop_back() {
        if processed.contains(&current_hash) {
            continue;
        }

        let tips = provider.get_past_blocks_for_block_hash(&current_hash).await?;
        stream::iter(tips.iter())
            .map(|tip_hash| async {
                let res = if provider.is_block_topological_ordered(tip_hash).await? {
                    let height = provider.get_height_for_block_hash(tip_hash).await?;
                    Helper::Height(height)
                } else {
                    Helper::Next(tip_hash.clone())
                };

                Ok::<_, BlockchainError>(res)
            })
            .buffer_unordered(provider.concurrency())
            .boxed()
            .try_fold((&mut lowest_height, &mut stack), |(lowest_height, stack), helper| async move {
                match helper {
                    Helper::Height(height) => {
                        if lowest_height.is_none_or(|h| h > height) {
                            *lowest_height = Some(height);
                        }
                    },
                    Helper::Next(tip_hash) => stack.push_back(tip_hash),
                }

                Ok((lowest_height, stack))
            }).await?;

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
    P: DifficultyProvider + DagOrderProvider + ConcurrencyProvider
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
pub async fn is_near_enough_from_main_chain<P>(provider: &P, hash: &Hash, chain_height: u64, version: BlockVersion) -> Result<bool, BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider + ConcurrencyProvider
{
    let Some(lowest_ordered_height) = calculate_distance_from_mainchain(provider, hash).await? else {
        return Ok(false);
    };

    debug!("distance for block {}: {} at chain height {}", hash, lowest_ordered_height, chain_height);

    // If the lowest ordered height is below or equal to current chain height
    // and that we have a difference bigger than our stable limit
    if lowest_ordered_height <= chain_height && chain_height - lowest_ordered_height >= get_stable_limit(version) {
        return Ok(false)
    }

    Ok(true)
}

// Find tip work score internal for a block hash
// this will recursively find all tips and their difficulty
pub async fn find_tip_work_score_internal<'a, P>(provider: &P, map: &mut HashMap<Hash, CumulativeDifficulty>, hash: &'a Hash, base_topoheight: TopoHeight) -> Result<(), BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider + ConcurrencyProvider
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

            stream::iter(tips.iter().filter(|tip_hash| !map.contains_key(*tip_hash)))
                .map(|tip_hash| async move {
                    let is_ordered = provider.is_block_topological_ordered(tip_hash).await?;
                    let res = if !is_ordered || provider.get_topo_height_for_hash(tip_hash).await? >= base_topoheight {
                        Some(tip_hash.clone())
                    } else {
                        None
                    };

                    Ok::<Option<Hash>, BlockchainError>(res)
                })
                .buffer_unordered(provider.concurrency())
                .boxed()
                .try_fold(&mut stack, |stack, tip_hash| async move {
                    if let Some(tip_hash) = tip_hash {
                        stack.push_back(tip_hash);
                    }
                    Ok(stack)
                }).await?;
        }
    }

    Ok(())
}

// find the sum of work done
pub async fn find_tip_work_score<'a, P, I>(
    provider: &P,
    block_hash: &Hash,
    block_tips: I,
    block_difficulty: Option<Difficulty>,
    base_block: &Hash,
    base_block_height: u64
) -> Result<(HashSet<Hash>, CumulativeDifficulty), BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider + CacheProvider + ConcurrencyProvider,
    I: Iterator<Item = &'a Hash> + Send + Sync
{
    trace!("find tip work score for {} at base {}", block_hash, base_block);
    let chain_cache = provider.chain_cache().await;

    let key = WorkScoreCacheKey {
        tip: block_hash.clone(),
        base: base_block.clone(),
    };

    {
        debug!("accessing tip work score cache for {} at height {}", block_hash, base_block_height);
        let mut cache = chain_cache.tip_work_score_cache.lock().await;
        if let Some(value) = cache.get(&key) {
            trace!("Found tip work score in cache: set [{}], height: {}", value.0.iter().map(|h| h.to_string()).collect::<Vec<String>>().join(", "), value.1);
            return Ok(value.clone())
        }
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
    {
        debug!("accessing tip work score cache to save tip work score for {} at height {}", block_hash, base_block_height);
        let mut cache = chain_cache.tip_work_score_cache.lock().await;
        debug!("tip work score cache locked for write");
        cache.put(key, (set.clone(), score));
    }

    Ok((set, score))
}

// this function generate a DAG paritial order into a full order using recursive calls.
// hash represents the best tip (biggest cumulative difficulty)
// base represents the block hash of a block already ordered and in stable height
// the full order is re generated each time a new block is added based on new TIPS
// first hash in order is the base hash
// base_height is only used for the cache key
pub async fn generate_full_order<P, I>(provider: &P, hashes: I, base: &Hash, base_topo_height: TopoHeight) -> Result<LinkedHashSet<Hash>, BlockchainError>
where
    P: DifficultyProvider + DagOrderProvider + ConcurrencyProvider,
    I: Iterator<Item = Hash> + ExactSizeIterator
{
    trace!("generate full order with base {}", base);
    if hashes.len() == 0 {
        return Err(BlockchainError::ExpectedTips)
    }

    // Full order that is generated
    let mut full_order = LinkedHashSet::new();
    // Current stack of hashes that need to be processed
    let mut stack = VecDeque::new();
    stack.extend(hashes);

    // Keep track of processed hashes that got reinjected for correct order
    let mut processed = HashSet::new();

    'main: while let Some(current_hash) = stack.pop_back() {
        // If it is processed and got reinjected, its to maintains right order
        // We just need to insert current hash as it the "final hash" that got processed
        // after all tips
        if current_hash == *base || !processed.insert(current_hash.clone()) {
            full_order.insert(current_hash);
            continue 'main;
        }

        // Retrieve block tips
        let block_tips = provider.get_past_blocks_for_block_hash(&current_hash).await?;

        // if the block is genesis or its the base block, we can add it to the full order
        if block_tips.is_empty() {
            full_order.insert(current_hash);
            continue 'main;
        }

        // TODO: we can optimize it more by fully deleting it once the others optimizations are done
        let scores = stream::iter(block_tips.iter())
            .map(|tip_hash| async move {
                let is_ordered = provider.is_block_topological_ordered(tip_hash).await?;
                Ok::<_, BlockchainError>(if !is_ordered || provider.get_topo_height_for_hash(tip_hash).await? >= base_topo_height {
                    Some(tip_hash.clone())
                } else {
                    None
                })
            })
            .buffered(provider.concurrency())
            .filter_map(|x| async move { x.transpose() })
            .boxed()
            .try_collect::<Vec<_>>().await?;

        stack.push_back(current_hash);

        stack.extend(scores.into_iter().rev());
    }

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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use indexmap::IndexSet;
    use xelis_common::{
        account::CiphertextCache,
        block::{BlockHeader, BlockVersion, EXTRA_NONCE_SIZE},
        config::XELIS_ASSET,
        crypto::elgamal::Ciphertext,
        crypto::{Hash, KeyPair},
        difficulty::Difficulty,
        immutable::Immutable,
        network::Network,
        transaction::{
            builder::{AccountState, FeeBuilder, FeeHelper, TransactionBuilder, TransactionTypeBuilder},
            BurnPayload,
            Reference,
            TxVersion
        },
        varuint::VarUint,
    };

    use crate::{
        config::DEV_PUBLIC_KEY,
        core::storage::{
            BlockProvider,
            ClientProtocolProvider,
            DagOrderProvider,
            MemoryStorage,
            PrunedTopoheightProvider,
            TransactionProvider,
        }
    };

    use super::*;

    fn h(id: u8) -> Hash {
        Hash::new([id; 32])
    }

    async fn add_block(
        storage: &mut MemoryStorage,
        hash: Hash,
        height: u64,
        timestamp: u64,
        tips: Vec<Hash>,
        difficulty: u64,
        cumulative_difficulty: u64,
        version: BlockVersion,
        topoheight: Option<u64>,
    ) {
        let tips_set: IndexSet<Hash> = tips.into_iter().collect();
        let header = BlockHeader::new(
            version,
            height,
            timestamp,
            tips_set,
            [0u8; EXTRA_NONCE_SIZE],
            DEV_PUBLIC_KEY.clone(),
            IndexSet::new(),
        );

        storage
            .save_block(
                Arc::new(header),
                &[],
                Difficulty::from_u64(difficulty),
                cumulative_difficulty.into(),
                VarUint::from(0u64),
                0,
                Immutable::Owned(hash.clone()),
            )
            .await
            .unwrap();

        if let Some(topo) = topoheight {
            storage.set_topo_height_for_block(&hash, topo).await.unwrap();
        }
    }

    #[test]
    fn test_sort_cumulative_difficulty_orders_and_tiebreakers() {
        let mut descending = vec![
            (h(1), 10u64.into()),
            (h(3), 20u64.into()),
            (h(2), 20u64.into()),
        ];

        sort_descending_by_cumulative_difficulty(&mut descending);
        assert_eq!(descending[0].0, h(3));
        assert_eq!(descending[1].0, h(2));
        assert_eq!(descending[2].0, h(1));

        let mut ascending = vec![
            (h(9), 10u64.into()),
            (h(1), 10u64.into()),
            (h(8), 5u64.into()),
        ];

        sort_ascending_by_cumulative_difficulty(&mut ascending);
        assert_eq!(ascending[0].0, h(8));
        assert_eq!(ascending[1].0, h(1));
        assert_eq!(ascending[2].0, h(9));
    }

    #[tokio::test]
    async fn test_sort_tips_and_best_tip_edges() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);
        let a = h(1);
        let b = h(2);

        add_block(&mut storage, a.clone(), 1, 10, vec![], 10, 50, BlockVersion::V6, None).await;
        add_block(&mut storage, b.clone(), 1, 11, vec![], 10, 60, BlockVersion::V6, None).await;

        let empty = Vec::<Hash>::new();
        assert!(sort_tips(&storage, empty.into_iter()).await.is_err());

        let single = vec![a.clone()];
        let single_sorted: Vec<_> = sort_tips(&storage, single.into_iter()).await.unwrap().collect();
        assert_eq!(single_sorted, vec![a.clone()]);

        let multi = vec![a.clone(), b.clone()];
        let sorted: Vec<_> = sort_tips(&storage, multi.into_iter()).await.unwrap().collect();
        assert_eq!(sorted, vec![b.clone(), a.clone()]);

        let best = find_best_tip_by_cumulative_difficulty(&storage, vec![a, b.clone()].into_iter())
            .await
            .unwrap();
        assert_eq!(best, b);
    }

    #[tokio::test]
    async fn test_calculate_height_and_newest_tip_edges() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);
        let a = h(10);
        let b = h(11);

        add_block(&mut storage, a.clone(), 5, 100, vec![], 1, 1, BlockVersion::V6, None).await;
        add_block(&mut storage, b.clone(), 7, 120, vec![], 1, 2, BlockVersion::V6, None).await;

        let empty_height = calculate_height_at_tips(&storage, Vec::<&Hash>::new().into_iter())
            .await
            .unwrap();
        assert_eq!(empty_height, 0);

        let computed_height = calculate_height_at_tips(&storage, vec![&a, &b].into_iter())
            .await
            .unwrap();
        assert_eq!(computed_height, 8);

        assert!(find_newest_tip_by_timestamp(&storage, Vec::<&Hash>::new().into_iter())
            .await
            .is_err());

        let (tip, ts) = find_newest_tip_by_timestamp(&storage, vec![&a, &b].into_iter())
            .await
            .unwrap();
        assert_eq!(*tip, b);
        assert_eq!(ts, 120);
    }

    #[tokio::test]
    async fn test_is_sync_block_at_height_edges() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);
        let genesis = h(20);
        let a = h(21);
        let b = h(22);

        add_block(&mut storage, genesis.clone(), 0, 0, vec![], 1, 1, BlockVersion::V6, Some(0)).await;
        add_block(&mut storage, a.clone(), 10, 10, vec![genesis.clone()], 2, 3, BlockVersion::V6, Some(10)).await;

        assert!(is_sync_block_at_height(&storage, &genesis, 100, BlockVersion::V6)
            .await
            .unwrap());

        // not stable enough yet
        assert!(!is_sync_block_at_height(&storage, &a, 20, BlockVersion::V6)
            .await
            .unwrap());

        // stable and alone at its height
        assert!(is_sync_block_at_height(&storage, &a, 40, BlockVersion::V6)
            .await
            .unwrap());

        // now 2 ordered blocks at same height => not sync
        add_block(&mut storage, b.clone(), 10, 11, vec![genesis.clone()], 2, 4, BlockVersion::V6, Some(11)).await;
        assert!(!is_sync_block_at_height(&storage, &a, 40, BlockVersion::V6)
            .await
            .unwrap());

        // pruned block at pruned topoheight is sync
        storage.set_pruned_topoheight(Some(11)).await.unwrap();
        assert!(is_sync_block_at_height(&storage, &b, 40, BlockVersion::V6)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_is_side_block_internal_edges() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);
        let genesis = h(30);
        let a = h(31);
        let b = h(32);
        let c = h(33);

        add_block(&mut storage, genesis.clone(), 0, 0, vec![], 1, 1, BlockVersion::V6, Some(0)).await;
        add_block(&mut storage, a.clone(), 1, 1, vec![genesis.clone()], 1, 2, BlockVersion::V6, Some(1)).await;
        add_block(&mut storage, b.clone(), 2, 2, vec![a.clone()], 1, 3, BlockVersion::V6, Some(3)).await;
        add_block(&mut storage, c.clone(), 2, 3, vec![a.clone()], 1, 4, BlockVersion::V6, Some(2)).await;

        // genesis can never be a side block
        assert!(!is_side_block_internal(&storage, &genesis, Some(0), 10, BlockVersion::V6)
            .await
            .unwrap());

        // At same height, c has lower topoheight than b => b is side block
        assert!(is_side_block_internal(&storage, &b, Some(3), 10, BlockVersion::V6)
            .await
            .unwrap());

        // c is the earliest ordered block at its height => not side block
        assert!(!is_side_block_internal(&storage, &c, Some(2), 10, BlockVersion::V6)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_find_tip_base_and_common_base() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);
        let g = h(50);
        let a = h(51);
        let b = h(52);
        let c = h(53);

        add_block(&mut storage, g.clone(), 0, 0, vec![], 1, 1, BlockVersion::V6, Some(0)).await;
        add_block(&mut storage, a.clone(), 1, 1, vec![g.clone()], 2, 3, BlockVersion::V6, Some(1)).await;
        add_block(&mut storage, b.clone(), 2, 2, vec![a.clone()], 3, 6, BlockVersion::V6, None).await;
        add_block(&mut storage, c.clone(), 2, 3, vec![a.clone()], 3, 7, BlockVersion::V6, None).await;

        let (base_hash, base_height) = find_tip_base(&storage, &b, 40, 0, BlockVersion::V6)
            .await
            .unwrap();
        assert_eq!(base_hash, a);
        assert_eq!(base_height, 1);

        let tips: IndexSet<Hash> = vec![b.clone(), c.clone()].into_iter().collect();
        let (common_hash, common_height) = find_common_base(&storage, tips.iter(), BlockVersion::V6)
            .await
            .unwrap();
        assert_eq!(common_hash, h(50));
        assert_eq!(common_height, 0);

        let common_only_height = find_common_base_height(&storage, &tips, BlockVersion::V6)
            .await
            .unwrap();
        assert_eq!(common_only_height, 0);

        let empty_tips = IndexSet::new();
        let h0 = find_common_base_height(&storage, &empty_tips, BlockVersion::V6)
            .await
            .unwrap();
        assert_eq!(h0, 0);
    }

    #[tokio::test]
    async fn test_find_tip_base_pruned_edge() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);
        let g = h(60);
        let a = h(61);

        add_block(&mut storage, g.clone(), 0, 0, vec![], 1, 1, BlockVersion::V6, Some(0)).await;
        add_block(&mut storage, a.clone(), 1, 1, vec![g.clone()], 2, 3, BlockVersion::V6, Some(1)).await;

        let (base_hash, base_height) = find_tip_base(&storage, &a, 40, 1, BlockVersion::V6)
            .await
            .unwrap();
        assert_eq!(base_hash, a);
        assert_eq!(base_height, 1);
    }

    #[tokio::test]
    async fn test_find_nearest_topoheight_and_nearest_base_topoheight() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);
        let g = h(70);
        let a = h(71);
        let b = h(72);
        let c = h(73);

        add_block(&mut storage, g.clone(), 0, 0, vec![], 1, 1, BlockVersion::V6, Some(0)).await;
        add_block(&mut storage, a.clone(), 1, 1, vec![g.clone()], 1, 2, BlockVersion::V6, Some(1)).await;
        add_block(&mut storage, b.clone(), 2, 2, vec![a.clone()], 1, 3, BlockVersion::V6, None).await;
        add_block(&mut storage, c.clone(), 2, 3, vec![a.clone()], 1, 4, BlockVersion::V6, None).await;

        let topo = find_nearest_topoheight(&storage, vec![b.clone()]).await.unwrap();
        assert_eq!(topo, 1);

        let nearest_base = find_nearest_base_topoheight(&storage, vec![b.clone(), c.clone()].into_iter(), 0)
            .await
            .unwrap();
        assert_eq!(nearest_base, 1);

        assert!(find_nearest_topoheight(&storage, Vec::<Hash>::new())
            .await
            .is_err());

        assert!(find_nearest_base_topoheight(&storage, vec![b, c].into_iter(), 100)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_build_reachability_and_verify_non_reachability() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);
        let g = h(80);
        let a = h(81);
        let b = h(82);
        let c = h(83);

        add_block(&mut storage, g.clone(), 0, 0, vec![], 1, 1, BlockVersion::V6, Some(0)).await;
        add_block(&mut storage, a.clone(), 1, 1, vec![g.clone()], 1, 2, BlockVersion::V6, None).await;
        add_block(&mut storage, b.clone(), 2, 2, vec![a.clone()], 1, 3, BlockVersion::V6, None).await;
        add_block(&mut storage, c.clone(), 3, 3, vec![g.clone()], 1, 4, BlockVersion::V6, None).await;

        let reach = build_reachability(&storage, b.clone(), BlockVersion::V6).await.unwrap();
        assert!(reach.contains(&b));
        assert!(reach.contains(&a));
        assert!(reach.contains(&g));

        let independent_tips: IndexSet<Hash> = vec![b.clone(), c.clone()].into_iter().collect();
        assert!(verify_non_reachability(&storage, &independent_tips, BlockVersion::V6)
            .await
            .unwrap());

        let invalid_tips: IndexSet<Hash> = vec![a.clone(), b.clone()].into_iter().collect();
        assert!(!verify_non_reachability(&storage, &invalid_tips, BlockVersion::V6)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_mainchain_distance_helpers() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);
        let g = h(90);
        let a = h(91);
        let b = h(92);

        add_block(&mut storage, g.clone(), 0, 0, vec![], 1, 1, BlockVersion::V6, Some(0)).await;
        add_block(&mut storage, a.clone(), 10, 1, vec![g.clone()], 1, 2, BlockVersion::V6, Some(1)).await;
        add_block(&mut storage, b.clone(), 11, 2, vec![a.clone()], 1, 3, BlockVersion::V6, None).await;

        let lowest = find_lowest_height_from_mainchain(&storage, b.clone()).await.unwrap();
        assert_eq!(lowest, Some(10));

        let ordered_distance = calculate_distance_from_mainchain(&storage, &a).await.unwrap();
        assert_eq!(ordered_distance, Some(10));

        let unordered_distance = calculate_distance_from_mainchain(&storage, &b).await.unwrap();
        assert_eq!(unordered_distance, Some(10));

        assert!(!is_near_enough_from_main_chain(&storage, &b, 40, BlockVersion::V6)
            .await
            .unwrap());
        assert!(is_near_enough_from_main_chain(&storage, &b, 20, BlockVersion::V6)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_find_tip_work_score() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);
        let g = h(100);
        let a = h(101);
        let b = h(102);
        let c = h(103);

        add_block(&mut storage, g.clone(), 0, 0, vec![], 1, 1, BlockVersion::V6, Some(0)).await;
        add_block(&mut storage, a.clone(), 1, 1, vec![g.clone()], 2, 3, BlockVersion::V6, Some(1)).await;
        add_block(&mut storage, b.clone(), 2, 2, vec![a.clone()], 3, 6, BlockVersion::V6, Some(2)).await;
        add_block(&mut storage, c.clone(), 3, 3, vec![b.clone()], 4, 10, BlockVersion::V6, None).await;

        let mut map = HashMap::new();
        find_tip_work_score_internal(&storage, &mut map, &c, 1).await.unwrap();
        assert!(map.contains_key(&c));
        assert!(map.contains_key(&b));
        assert!(map.contains_key(&a));
        assert!(!map.contains_key(&g));

        let (set, score) = find_tip_work_score(
            &storage,
            &c,
            vec![&b].into_iter(),
            None,
            &a,
            1,
        )
        .await
        .unwrap();

        assert_eq!(set.len(), 3);
        assert!(set.contains(&a));
        assert_eq!(score, 10u64.into());
    }

    #[tokio::test]
    async fn test_generate_full_order_and_validate_tips() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);
        let g = h(110);
        let a = h(111);
        let b = h(112);

        add_block(&mut storage, g.clone(), 0, 0, vec![], 100, 100, BlockVersion::V6, Some(0)).await;
        add_block(&mut storage, a.clone(), 1, 1, vec![g.clone()], 95, 195, BlockVersion::V6, Some(1)).await;
        add_block(&mut storage, b.clone(), 2, 2, vec![a.clone()], 80, 275, BlockVersion::V6, None).await;

        let full_order = generate_full_order(&storage, vec![b.clone()].into_iter(), &a, 1)
            .await
            .unwrap();
        let ordered_hashes: Vec<Hash> = full_order.iter().cloned().collect();
        assert_eq!(ordered_hashes, vec![a.clone(), b.clone()]);

        assert!(validate_tips(&storage, &b, &a).await.unwrap());
        assert!(!validate_tips(&storage, &a, &b).await.unwrap());

        assert!(generate_full_order(&storage, Vec::<Hash>::new().into_iter(), &a, 1)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_is_tx_executed_for_topoheight() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);
        let tx = h(200);
        let res = is_tx_executed_for_topoheight(&storage, &tx, 10).await.unwrap();
        assert!(!res);

        let tx_hash = h(210);
        let block_hash = h(211);

        add_block(&mut storage, block_hash.clone(), 1, 1, vec![], 1, 1, BlockVersion::V6, Some(5)).await;

        let keypair = KeyPair::new();
        let source = keypair.get_public_key().compress();
        let tx = TransactionBuilder::new(
            TxVersion::V2,
            source,
            None,
            TransactionTypeBuilder::Burn(BurnPayload {
                asset: XELIS_ASSET,
                amount: 1,
            }),
            FeeBuilder::default(),
        );

        struct DummyState {
            is_mainnet: bool,
            nonce: u64,
            reference: Reference,
            balances: HashMap<Hash, (u64, CiphertextCache)>,
        }

        impl FeeHelper for DummyState {
            type Error = ();

            fn account_exists(&self, _: &xelis_common::crypto::elgamal::CompressedPublicKey) -> Result<bool, Self::Error> {
                Ok(true)
            }
        }

        impl AccountState for DummyState {
            fn is_mainnet(&self) -> bool {
                self.is_mainnet
            }

            fn get_account_balance(&self, asset: &Hash) -> Result<u64, Self::Error> {
                self.balances.get(asset).map(|(balance, _)| *balance).ok_or(())
            }

            fn get_reference(&self) -> Reference {
                self.reference.clone()
            }

            fn get_account_ciphertext(&self, asset: &Hash) -> Result<CiphertextCache, Self::Error> {
                self.balances.get(asset).map(|(_, ct)| ct.clone()).ok_or(())
            }

            fn update_account_balance(&mut self, asset: &Hash, new_balance: u64, ciphertext: Ciphertext) -> Result<(), Self::Error> {
                self.balances.insert(asset.clone(), (new_balance, CiphertextCache::Decompressed(None, ciphertext)));
                Ok(())
            }

            fn get_nonce(&self) -> Result<u64, Self::Error> {
                Ok(self.nonce)
            }

            fn update_nonce(&mut self, new_nonce: u64) -> Result<(), Self::Error> {
                self.nonce = new_nonce;
                Ok(())
            }
        }

        let mut state = DummyState {
            is_mainnet: false,
            nonce: 0,
            reference: Reference {
                hash: Hash::zero(),
                topoheight: 0,
            },
            balances: {
                let mut balances = HashMap::new();
                balances.insert(
                    XELIS_ASSET,
                    (
                        1_000_000,
                        CiphertextCache::Decompressed(
                            None,
                            keypair.get_public_key().encrypt(1_000_000u64),
                        ),
                    ),
                );
                balances
            },
        };

        let built_tx = tx.build(&mut state, &keypair).unwrap();
        storage.add_transaction(&tx_hash, &built_tx).await.unwrap();
        storage.mark_tx_as_executed_in_block(&tx_hash, &block_hash).await.unwrap();

        assert!(is_tx_executed_for_topoheight(&storage, &tx_hash, 5).await.unwrap());
        assert!(!is_tx_executed_for_topoheight(&storage, &tx_hash, 4).await.unwrap());
    }
}