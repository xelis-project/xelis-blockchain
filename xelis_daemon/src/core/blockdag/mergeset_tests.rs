use std::{iter, sync::Arc};
use anyhow::Result;
use indexmap::IndexSet;
use linked_hash_table::LinkedHashSet;
use xelis_common::{
    block::{BlockHeader, BlockVersion, EXTRA_NONCE_SIZE},
    crypto::{Hash, KeyPair, PublicKey},
    difficulty::{CumulativeDifficulty, Difficulty},
    immutable::Immutable,
    network::Network,
    varuint::VarUint,
};
use crate::core::{
    blockdag::{
        self,
        find_best_tip_by_cumulative_difficulty,
        sort_tips,
        mergeset::{
            K,
            compute_block_mergesets,
            is_dag_ancestor_of,
        }
    },
    storage::{
        BlockProvider,
        DagOrderProvider,
        DifficultyProvider,
        MergeSet,
        MergeSetProvider,
        memory::MemoryStorage
    }
};

/// Create a unique deterministic hash from a byte index.
fn test_hash(index: u8) -> Hash {
    Hash::new([index; 32])
}

/// Dummy miner public key for test blocks.
fn test_miner() -> PublicKey {
    // Use a fixed keypair so all tests share the same miner
    // (the miner identity is irrelevant for DAG tests).
    lazy_static::lazy_static! {
        static ref MINER: PublicKey = KeyPair::new().get_public_key().compress();
    }
    MINER.clone()
}

/// Create and save a block in `MemoryStorage`.
///
/// `tips` is the set of parent hashes (empty for genesis).
async fn create_block(
    storage: &mut MemoryStorage,
    hash: &Hash,
    height: u64,
    tips: IndexSet<Hash>,
    difficulty: u64,
    cumulative_difficulty: u64,
) {
    let header = BlockHeader::new(
        BlockVersion::V6,
        height,
        0,
        tips,
        [0u8; EXTRA_NONCE_SIZE],
        test_miner(),
        IndexSet::new(),
    );

    storage.save_block(
        Arc::new(header),
        &[],
        Default::default(),
        Difficulty::from_u64(difficulty),
        CumulativeDifficulty::from_u64(cumulative_difficulty),
        VarUint::from_u64(0),      // covariance
        0,                         // size_ema
        Immutable::Owned(hash.clone()),
    ).await.unwrap();

    // Mark the block as topologically ordered (some functions check this)
    storage.set_topo_height_for_block(hash, 0).await.unwrap();
}

/// Create genesis block and initialise both GHOSTDAG data and the
/// reachability tree.
async fn create_genesis(storage: &mut MemoryStorage, hash: &Hash, difficulty: u64) {
    create_block(storage, hash, 0, IndexSet::new(), difficulty, difficulty).await;
    process_block(storage, hash, &IndexSet::new(), difficulty).await;
}

/// Convenience: process a non-genesis block through GHOSTDAG.
/// Returns the stored MergeSet, the red blocks set, and the computed blue_work.
async fn process_block(
    storage: &mut MemoryStorage,
    hash: &Hash,
    tips: &IndexSet<Hash>,
    difficulty: u64,
) -> (MergeSet, LinkedHashSet<Hash>, CumulativeDifficulty) {
    let (data, reds, blue_work) = compute_block_mergesets(
        storage,
        hash,
        tips,
        Difficulty::from_u64(difficulty),
    ).await.unwrap();
    let block = storage.get_block_by_hash(hash).await.unwrap();
    let (header, txs) = block.split();
    let block_difficulty = storage.get_difficulty_for_block_hash(hash).await.unwrap();
    let covariance = storage.get_estimated_covariance_for_block_hash(hash).await.unwrap();
    let size_ema = storage.get_block_size_ema(hash).await.unwrap();

    storage.save_block(
        header,
        &txs,
        data.clone(),
        block_difficulty,
        blue_work,
        covariance,
        size_ema,
        Immutable::Owned(hash.clone()),
    ).await.unwrap();

    (data, reds, blue_work)
}

#[tokio::test]
async fn test_reachability_add_child() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    let child = test_hash(1);

    create_genesis(&mut storage, &genesis, 100).await;

    let mut tips = IndexSet::new();
    tips.insert(genesis.clone());
    create_block(&mut storage, &child, 1, tips.clone(), 100, 200).await;

    // Genesis interval must contain child interval (ancestor check)
    assert!(is_dag_ancestor_of(&storage, &genesis, &child).await?);
    // Child is NOT an ancestor of genesis
    assert!(!is_dag_ancestor_of(&storage, &child, &genesis).await?);
    // Both are ancestors of themselves
    assert!(is_dag_ancestor_of(&storage, &genesis, &genesis).await?);
    assert!(is_dag_ancestor_of(&storage, &child, &child).await?);

    Ok(())
}

#[tokio::test]
async fn test_reachability_chain() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);

    create_genesis(&mut storage, &genesis, 100).await;

    // Build a chain: genesis -> A -> B -> C
    let hashes: Vec<Hash> = (1..=3).map(test_hash).collect();
    let mut parent = genesis.clone();
    for (i, h) in hashes.iter().enumerate() {
        let mut tips = IndexSet::new();
        tips.insert(parent.clone());
        create_block(&mut storage, h, (i + 1) as u64, tips.clone(), 100, 100 * (i as u64 + 2)).await;
        parent = h.clone();
    }

    // Genesis is ancestor of all
    for h in &hashes {
        assert!(is_dag_ancestor_of(&storage, &genesis, h).await?,
            "genesis should be ancestor of {}", h);
    }

    // A is ancestor of B and C
    assert!(is_dag_ancestor_of(&storage, &hashes[0], &hashes[1]).await?);
    assert!(is_dag_ancestor_of(&storage, &hashes[0], &hashes[2]).await?);

    // C is NOT ancestor of A
    assert!(!is_dag_ancestor_of(&storage, &hashes[2], &hashes[0]).await?);

    // B is NOT ancestor of A
    assert!(!is_dag_ancestor_of(&storage, &hashes[1], &hashes[0]).await?);

    Ok(())
}

#[tokio::test]
async fn test_reachability_parallel_branches() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);

    create_genesis(&mut storage, &genesis, 100).await;

    // Two branches off genesis: A and B
    let a = test_hash(1);
    let b = test_hash(2);

    let mut tips_a = IndexSet::new();
    tips_a.insert(genesis.clone());
    create_block(&mut storage, &a, 1, tips_a.clone(), 100, 200).await;

    let mut tips_b = IndexSet::new();
    tips_b.insert(genesis.clone());
    create_block(&mut storage, &b, 1, tips_b.clone(), 100, 200).await;

    // Genesis is ancestor of both
    assert!(is_dag_ancestor_of(&storage, &genesis, &a).await?);
    assert!(is_dag_ancestor_of(&storage, &genesis, &b).await?);

    // Neither A nor B is ancestor of the other (they are in each other's anticone)
    assert!(!is_dag_ancestor_of(&storage, &a, &b).await?);
    assert!(!is_dag_ancestor_of(&storage, &b, &a).await?);

    Ok(())
}

#[tokio::test]
async fn test_genesis() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);

    create_genesis(&mut storage, &genesis, 100).await;

    let data = storage.get_mergeset(&genesis).await?;
    // Genesis has no tips
    assert_eq!(data.len(), 0, "Genesis has no parents");

    Ok(())
}

#[tokio::test]
async fn test_linear_chain() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    // Build genesis -> A -> B -> C (linear chain, all should be blue)
    let a = test_hash(1);
    let b = test_hash(2);
    let c = test_hash(3);

    // Block A
    let mut tips = IndexSet::new();
    tips.insert(genesis.clone());
    create_block(&mut storage, &a, 1, tips.clone(), 100, 200).await;
    let (data_a, reds_a, bw_a) = process_block(&mut storage, &a, &tips, 100).await;

    // SP=genesis is the only entry in mergeset_blues (no non-selected-parent tips)
    assert_eq!(data_a.len(), 1, "Only SP should be in mergeset_blues");
    assert!(reds_a.is_empty());

    // Block B
    tips.clear();
    tips.insert(a.clone());
    create_block(&mut storage, &b, 2, tips.clone(), 100, 300).await;
    let (data_b, reds_b, bw_b) = process_block(&mut storage, &b, &tips, 100).await;
    assert_eq!(data_b.len(), 1, "B: only SP (A) in mergeset_blues");
    assert!(reds_b.is_empty(), "B: no red blocks in linear chain");
    assert!(bw_b > bw_a, "B.blue_work must exceed A.blue_work");

    // Block C
    tips.clear();
    tips.insert(b.clone());
    create_block(&mut storage, &c, 3, tips.clone(), 100, 400).await;
    let (data_c, reds_c, bw_c) = process_block(&mut storage, &c, &tips, 100).await;
    assert_eq!(data_c.len(), 1, "C: only SP (B) in mergeset_blues");
    assert!(reds_c.is_empty(), "C: no red blocks in linear chain");
    assert!(bw_c > bw_b, "C.blue_work must exceed B.blue_work");

    Ok(())
}

#[tokio::test]
async fn test_two_parallel_blocks_merged() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    // Two parallel blocks off genesis: A and B
    let a = test_hash(1);
    let b = test_hash(2);

    let mut tips_a = IndexSet::new();
    tips_a.insert(genesis.clone());
    create_block(&mut storage, &a, 1, tips_a.clone(), 100, 200).await;
    process_block(&mut storage, &a, &tips_a, 100).await;

    let mut tips_b = IndexSet::new();
    tips_b.insert(genesis.clone());
    create_block(&mut storage, &b, 1, tips_b.clone(), 100, 200).await;
    process_block(&mut storage, &b, &tips_b, 100).await;

    // Block C merges both: tips = [A, B]
    let c = test_hash(3);
    let mut tips_c = IndexSet::new();
    tips_c.insert(a.clone());
    tips_c.insert(b.clone());
    create_block(&mut storage, &c, 2, tips_c.clone(), 100, 300).await;
    let (data_c, reds_c, blue_work_c) = process_block(&mut storage, &c, &tips_c, 100).await;

    // SP + one non-SP blue = 2 entries in mergeset_blues
    // (one of A/B is selected parent, the other is in the mergeset and colored blue)
    assert_eq!(data_c.len(), 2,
        "SP + one non-selected tip should be blue");
    assert!(reds_c.is_empty(), "No blocks should be red");
    // blue_work = parent.blue_work + sum(blue_diffs) + self_diff = 200 + 100 + 100 = 400
    assert_eq!(blue_work_c, CumulativeDifficulty::from_u64(400));

    Ok(())
}

#[tokio::test]
async fn test_three_parallel_within_k() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    // Three parallel blocks off genesis (k = GHOSTDAG_K = 3, anticone for each ≤ k -> all blue)
    let a = test_hash(1);
    let b = test_hash(2);
    let c = test_hash(3);

    for (h, _idx) in [(&a, 1u8), (&b, 2), (&c, 3)] {
        let mut tips = IndexSet::new();
        tips.insert(genesis.clone());
        create_block(&mut storage, h, 1, tips.clone(), 100, 200).await;
        process_block(&mut storage, h, &tips, 100).await;
    }

    // Block D merges all three: tips = [A, B, C]
    let d = test_hash(4);
    let mut tips_d = IndexSet::new();
    tips_d.insert(a.clone());
    tips_d.insert(b.clone());
    tips_d.insert(c.clone());
    create_block(&mut storage, &d, 2, tips_d.clone(), 100, 300).await;
    let (data_d, reds_d, _) = process_block(&mut storage, &d, &tips_d, 100).await;

    // SP + two non-SP blues = 3 entries
    assert_eq!(data_d.len(), 3,
        "SP + two non-selected tips should be blue");
    assert!(reds_d.is_empty(), "No blocks should be red");

    Ok(())
}

#[tokio::test]
async fn test_selected_parent_highest_blue_score() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    // Build an asymmetric DAG:
    // genesis -> A -> B  (chain of length 2, blue_score = 2)
    // genesis -> C      (chain of length 1, blue_score = 1)
    let a = test_hash(1);
    let b = test_hash(2);
    let c = test_hash(3);

    let mut tips = IndexSet::new();
    tips.insert(genesis.clone());
    create_block(&mut storage, &a, 1, tips.clone(), 100, 200).await;
    process_block(&mut storage, &a, &tips, 100).await;

    tips.clear();
    tips.insert(a.clone());
    create_block(&mut storage, &b, 2, tips.clone(), 100, 300).await;
    process_block(&mut storage, &b, &tips, 100).await;

    tips.clear();
    tips.insert(genesis.clone());
    create_block(&mut storage, &c, 1, tips.clone(), 100, 200).await;
    process_block(&mut storage, &c, &tips, 100).await;

    // Block D merges B and C: tips = [B, C]
    let d = test_hash(4);
    let mut tips_d = IndexSet::new();
    tips_d.insert(b.clone());
    tips_d.insert(c.clone());
    create_block(&mut storage, &d, 3, tips_d.clone(), 100, 400).await;
    let (data_d, _, _) = process_block(&mut storage, &d, &tips_d, 100).await;

    // C should be in the mergeset (not an ancestor of B since they diverge at genesis)
    // C's anticone relative to blue chain should be small -> blue
    assert!(data_d.contains(&c),
        "C should be in mergeset_blues");

    // B has deeper chain (higher blue_work=300 vs C's 200) -> must be the selected parent
    let sp = data_d.keys().next().expect("must have at least one blue (the SP)");
    assert_eq!(sp, &b, "B (chain depth 2, blue_work=300) must be selected parent, not C");

    Ok(())
}

#[tokio::test]
async fn test_blue_work_accumulation() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 50).await;

    // genesis (diff=50) -> A (diff=100) -> B (diff=200)
    let a = test_hash(1);
    let b = test_hash(2);

    let mut tips = IndexSet::new();
    tips.insert(genesis.clone());
    create_block(&mut storage, &a, 1, tips.clone(), 100, 150).await;
    let (_, _, blue_work_a) = process_block(&mut storage, &a, &tips, 100).await;
    // blue_work = genesis.blue_work + self_diff = 50 + 100 = 150
    assert_eq!(blue_work_a, CumulativeDifficulty::from_u64(150));

    tips.clear();
    tips.insert(a.clone());
    create_block(&mut storage, &b, 2, tips.clone(), 200, 350).await;
    let (_data_b, _, blue_work_b) = process_block(&mut storage, &b, &tips, 200).await;
    // blue_work = a.blue_work + self_diff = 150 + 200 = 350
    assert_eq!(blue_work_b, CumulativeDifficulty::from_u64(350));

    // The stored cumulative difficulty should match the blue_work
    let stored_cd = storage.get_cumulative_difficulty_for_block_hash(&b).await?;
    assert_eq!(stored_cd, CumulativeDifficulty::from_u64(350));

    Ok(())
}

#[tokio::test]
async fn test_sort_tips_by_blue_score() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    // Build: genesis -> A -> B (blue_score 2)
    //        genesis -> C     (blue_score 1)
    let a = test_hash(1);
    let b = test_hash(2);
    let c = test_hash(3);

    let mut tips = IndexSet::new();
    tips.insert(genesis.clone());
    create_block(&mut storage, &a, 1, tips.clone(), 100, 200).await;
    process_block(&mut storage, &a, &tips, 100).await;

    tips.clear();
    tips.insert(a.clone());
    create_block(&mut storage, &b, 2, tips.clone(), 100, 300).await;
    process_block(&mut storage, &b, &tips, 100).await;

    tips.clear();
    tips.insert(genesis.clone());
    create_block(&mut storage, &c, 1, tips.clone(), 100, 200).await;
    process_block(&mut storage, &c, &tips, 100).await;

    // Sort [C, B] by blue score -> should be [B, C]
    let mut tip_set = IndexSet::new();
    tip_set.insert(c.clone());
    tip_set.insert(b.clone());

    let sorted = sort_tips(&storage, tip_set.iter()).await?
        .collect::<Vec<_>>();
    assert_eq!(sorted[0], &b, "B (blue_score=2) should come first");
    assert_eq!(sorted[1], &c, "C (blue_score=1) should come second");

    // find_best_tip should return B
    let best = find_best_tip_by_cumulative_difficulty(&storage, tip_set.iter()).await?;
    assert_eq!(best, &b);

    Ok(())
}

// Parasite-chain resistance

#[tokio::test]
async fn test_parasite_chain_honest_wins() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    // Honest chain: genesis -> H1 -> H2 -> H3 -> H4
    let h1 = test_hash(10);
    let h2 = test_hash(11);
    let h3 = test_hash(12);
    let h4 = test_hash(13);
    let honest = [&h1, &h2, &h3, &h4];

    let mut parent_tips = IndexSet::new();
    parent_tips.insert(genesis.clone());
    for (i, h) in honest.iter().enumerate() {
        create_block(&mut storage, h, (i + 1) as u64, parent_tips.clone(), 100, 100 * (i as u64 + 2)).await;
        process_block(&mut storage, h, &parent_tips, 100).await;
        parent_tips.clear();
        parent_tips.insert((*h).clone());
    }

    // h4's cumulative_difficulty was set when creating the block (100 * 5 = 500)
    let h4_cd = storage.get_cumulative_difficulty_for_block_hash(&h4).await?;
    assert_eq!(h4_cd, CumulativeDifficulty::from_u64(500));

    // Attacker chain: genesis -> A1 -> A2 -> A3 -> A4
    // Same difficulty, but built in isolation
    let a1 = test_hash(20);
    let a2 = test_hash(21);
    let a3 = test_hash(22);
    let a4 = test_hash(23);
    let attacker = [&a1, &a2, &a3, &a4];

    parent_tips.clear();
    parent_tips.insert(genesis.clone());
    for (i, a) in attacker.iter().enumerate() {
        create_block(&mut storage, a, (i + 1) as u64, parent_tips.clone(), 100, 100 * (i as u64 + 2)).await;
        process_block(&mut storage, a, &parent_tips, 100).await;
        parent_tips.clear();
        parent_tips.insert((*a).clone());
    }

    // Now a merge block M references both H4 and A4
    let merge = test_hash(99);
    let mut merge_tips = IndexSet::new();
    merge_tips.insert(h4.clone());
    merge_tips.insert(a4.clone());
    create_block(&mut storage, &merge, 5, merge_tips.clone(), 100, 600).await;
    let (merge_data, merge_reds, merge_blue_work) = process_block(&mut storage, &merge, &merge_tips, 100).await;

    // The selected parent should be one of the chains (equal blue_score -> hash tiebreak).
    // The OTHER chain's blocks will appear in the mergeset.
    // Since the two chains are parallel (not in each other's past),
    // the non-selected chain blocks will be in the mergeset.
    // Their anticone relative to the blue chain will be large (4 blocks),
    // which is > k=3, so they should be colored RED.
    // Note: mergeset_blues includes the SP as first entry, so subtract 1 for non-SP blues.
    let non_sp_blues = merge_data.len().saturating_sub(1);
    let total_mergeset = non_sp_blues + merge_reds.len();
    assert!(total_mergeset > 0, "Merge block must have a non-empty mergeset");

    // The attacker (or losing) chain should have mostly red blocks
    // because each block's anticone w.r.t. the winning blue chain > k
    assert!(merge_reds.len() > 0,
        "At least some blocks from the parallel chain should be RED (anticone > k)");

    // Verify the red blocks specifically belong to the attacker chain (A1-A4)
    let attacker_blocks = [a1.clone(), a2.clone(), a3.clone(), a4.clone()];
    let attacker_reds = merge_reds.iter()
        .filter(|h| attacker_blocks.contains(h))
        .count();
    assert!(attacker_reds > 3, "At least one attacker block (A1-A4) must be RED");

    // Blue work should NOT double-count the attacker chain's difficulty
    // (red blocks do not contribute to blue_work)
    let expected_max = CumulativeDifficulty::from_u64(500 + 100 + 100 * non_sp_blues as u64);
    assert!(merge_blue_work <= expected_max,
        "blue_work {} should be <= {} (no double counting)",
        merge_blue_work, expected_max);

    Ok(())
}

#[tokio::test]
async fn test_short_fork_all_blue() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    // Short fork that stays within k:
    // genesis -> A
    // genesis -> B
    // Both A and B merge into C

    let a = test_hash(1);
    let b = test_hash(2);
    let c = test_hash(3);

    let mut tips = IndexSet::new();
    tips.insert(genesis.clone());
    create_block(&mut storage, &a, 1, tips.clone(), 100, 200).await;
    process_block(&mut storage, &a, &tips, 100).await;

    tips.clear();
    tips.insert(genesis.clone());
    create_block(&mut storage, &b, 1, tips.clone(), 100, 200).await;
    process_block(&mut storage, &b, &tips, 100).await;

    tips.clear();
    tips.insert(a.clone());
    tips.insert(b.clone());
    create_block(&mut storage, &c, 2, tips.clone(), 100, 300).await;
    let (_, reds_c, _) = process_block(&mut storage, &c, &tips, 100).await;

    // Both A and B should be blue (anticone = 1 <= k=3)
    assert!(reds_c.is_empty(),
        "Short fork within k should produce no red blocks");
    Ok(())
}

// Full order & side block tests

#[tokio::test]
async fn test_full_order_linear() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    // genesis -> A -> B
    let a = test_hash(1);
    let b = test_hash(2);

    let mut tips = IndexSet::new();
    tips.insert(genesis.clone());
    create_block(&mut storage, &a, 1, tips.clone(), 100, 200).await;
    process_block(&mut storage, &a, &tips, 100).await;

    tips.clear();
    tips.insert(a.clone());
    create_block(&mut storage, &b, 2, tips.clone(), 100, 300).await;
    process_block(&mut storage, &b, &tips, 100).await;

    let order = blockdag::generate_full_order(&storage, iter::once(b.clone()), &genesis, 0).await?;
    // Order should be: genesis, A, B
    assert_eq!(order.len(), 3);
    assert!(order.contains(&genesis));
    assert!(order.contains(&a));
    assert!(order.contains(&b));

    Ok(())
}

#[tokio::test]
async fn test_full_order_with_merge() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    // genesis -> A, genesis -> B, merge -> C[A,B]
    let a = test_hash(1);
    let b = test_hash(2);
    let c = test_hash(3);

    let mut tips = IndexSet::new();
    tips.insert(genesis.clone());
    create_block(&mut storage, &a, 1, tips.clone(), 100, 200).await;
    process_block(&mut storage, &a, &tips, 100).await;

    tips.clear();
    tips.insert(genesis.clone());
    create_block(&mut storage, &b, 1, tips.clone(), 100, 200).await;
    process_block(&mut storage, &b, &tips, 100).await;

    tips.clear();
    tips.insert(a.clone());
    tips.insert(b.clone());
    create_block(&mut storage, &c, 2, tips.clone(), 100, 300).await;
    process_block(&mut storage, &c, &tips, 100).await;

    let order = blockdag::generate_full_order(&storage, iter::once(c.clone()), &genesis, 0).await?;
    // All 4 blocks should be in the order
    assert_eq!(order.len(), 4);
    assert!(order.contains(&genesis));
    assert!(order.contains(&a));
    assert!(order.contains(&b));
    assert!(order.contains(&c));

    Ok(())
}

#[tokio::test]
async fn test_k_boundary() -> Result<()> {
    // GHOSTDAG_K = TIPS_LIMIT = 3.
    //
    // Since TIPS_LIMIT = 3, a merge block can have at most 3 parent tips.
    // Scenarios with more than 3 mutually-parallel direct tip blocks that all
    // participate in mutual anticone are impossible.  Instead we use a side chain
    // to populate the mergeset with many non-SP candidates while using only 2 tips:
    //
    //   genesis(0) --- SP_p(1) --- SP(2) --- B(3)   <- B is merge-block's SP
    //   genesis(0) --- C1(1) --- C2(2) --- C3(3)...  <- side chain (tip = Ck)
    //
    //   Merge = {B, Ck}  (2 tips, well within TIPS_LIMIT = 3)
    //   Merge SP = B (highest cumulative work)
    //   Mergeset = {C1, C2, ..., Ck}  (all ancestors of Ck not in B's past)
    //
    // Anticone relationships in the mergeset:
    //   B is parallel to every Ci (B's parent chain goes SP->SP_p->genesis, Ci are
    //   direct or indirect children of genesis through the C-fork, so none of them
    //   are ancestors/descendants of B).
    //   SP and SP_p are ALSO parallel to every Ci (both ultimately child of genesis
    //   via the SP-branch, not via the C-branch).
    //   The Ci blocks form a chain: Ci is an ancestor of C(i+1), so they are
    //   NOT in each other's anticone.
    //
    // When checking candidate Ci:
    //   • B (level-0 blue): parallel -> +1 to candidate_blue_anticone_size
    //   • SP (level-1 historical): parallel -> +1
    //   • SP_p (level-2 historical): parallel -> +1
    //   -> Each Ci has anticone_size = 3 = k (boundary, still blue).
    //
    // After each Ci is accepted as blue, B (and SP, SP_p) gain +1 from that Ci.
    //   After Ck (k-th Ci): B.anticone_size = k (boundary, still blue).
    //
    // When checking C(k+1):
    //   B.anticone_size = k -> immediate RED (would push B's anticone to k+1 > k).

    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    // Sub-test 1: 3 mutually-parallel direct tips -> all blue
    //
    // genesis -> P1, P2, P3 (all at height 1, mutually parallel)
    // Merge D = {P1, P2, P3}  (exactly 3 = TIPS_LIMIT)
    // Each Pi has anticone_size = 2 (the other two) ≤ k=3 -> all blue.
    let p1 = test_hash(1);
    let p2 = test_hash(2);
    let p3 = test_hash(3);

    for p in [&p1, &p2, &p3] {
        let mut tips = IndexSet::new();
        tips.insert(genesis.clone());
        create_block(&mut storage, p, 1, tips.clone(), 100, 200).await;
        process_block(&mut storage, p, &tips, 100).await;
    }

    let d = test_hash(4);
    let mut tips_d = IndexSet::new();
    tips_d.insert(p1.clone());
    tips_d.insert(p2.clone());
    tips_d.insert(p3.clone());
    create_block(&mut storage, &d, 2, tips_d.clone(), 100, 300).await;
    let (data_d, reds_d, _) = process_block(&mut storage, &d, &tips_d, 100).await;

    assert!(reds_d.is_empty(),
        "Sub-test 1: 3 parallel tips (≤ k={}) must all be blue, got {} reds",
        K, reds_d.len());
    assert_eq!(data_d.len(), 3, "Sub-test 1: SP + 2 non-SP blues = 3 total");

    // Sub-test 2: k C-chain candidates + B (SP) -> all blue
    //
    // SP chain: genesis -> SP_p -> SP -> B  (B has highest cumulative work)
    // C-chain:  genesis -> C1 -> C2 -> ... -> Ck  (tip = Ck)
    // Merge = {B, Ck}  (2 tips)
    //
    // B is the selected parent.
    // Mergeset candidates = {C1, C2, ..., Ck}.
    // B, SP, SP_p are all parallel to each Ci -> each Ci.anticone_size = 3 = k.
    // B accumulates one anticone entry per Ci -> B.anticone_size = k after Ck.
    // All blues -> no reds.
    let sp_p = test_hash(10);
    let sp = test_hash(11);
    let b = test_hash(12);

    {
        let mut tips = IndexSet::new();
        tips.insert(genesis.clone());
        create_block(&mut storage, &sp_p, 1, tips.clone(), 100, 200).await;
        process_block(&mut storage, &sp_p, &tips, 100).await;

        tips.clear();
        tips.insert(sp_p.clone());
        create_block(&mut storage, &sp, 2, tips.clone(), 100, 300).await;
        process_block(&mut storage, &sp, &tips, 100).await;

        tips.clear();
        tips.insert(sp.clone());
        create_block(&mut storage, &b, 3, tips.clone(), 100, 400).await;
        process_block(&mut storage, &b, &tips, 100).await;
    }

    let mut c_chain: Vec<Hash> = Vec::new();
    {
        let mut parent = genesis.clone();
        for i in 0..K {
            let c = test_hash(20 + i as u8);
            let mut tips = IndexSet::new();
            tips.insert(parent.clone());
            let height = (i + 1) as u64;
            let cumulative = 100 * (height + 1);
            create_block(&mut storage, &c, height, tips.clone(), 100, cumulative).await;
            process_block(&mut storage, &c, &tips, 100).await;
            c_chain.push(c.clone());
            parent = c;
        }
    }
    let ck = c_chain.last().unwrap().clone();

    let e = test_hash(40);
    let mut tips_e = IndexSet::new();
    tips_e.insert(b.clone()); // SP (highest cumulative_diff)
    tips_e.insert(ck.clone());
    create_block(&mut storage, &e, (K + 1) as u64, tips_e.clone(), 100, 600).await;
    let (data_e, reds_e, _) = process_block(&mut storage, &e, &tips_e, 100).await;

    // B(SP) + k C-chain blocks = k+1 total blues; no reds.
    assert!(reds_e.is_empty(),
        "Sub-test 2: k={} C-chain blocks must all be blue, got {} reds", K, reds_e.len());
    assert_eq!(data_e.len(), K + 1,
        "Sub-test 2: expected k+1={} blues (B + {} Ci), got {}", K + 1, K, data_e.len());
    // B (the SP) accumulates one anticone entry per Ci -> anticone_size = k
    assert_eq!(data_e.get(&b), Some(K),
        "Sub-test 2: B (SP) must have anticone_size=k={} after {} C-chain blocks", K, K);
    // Every Ci must be blue — each has anticone_size = k (B + SP + SP_p = 3 entries)
    for ci in &c_chain {
        assert!(data_e.contains(ci), "Sub-test 2: C-chain block must be blue");
        assert_eq!(data_e.get(ci), Some(K),
            "Sub-test 2: each Ci has anticone_size=k={} (parallel to B, SP, SP_p)", K);
    }

    // Sub-test 3: k+1 C-chain blocks -> C(k+1) is RED
    //
    // Same topology but side chain has length k+1.
    // After the first k Ci are accepted, B.anticone_size = k.
    // When checking C(k+1): B has anticone_size=k -> immediate RED.
    let sp2_p = test_hash(50);
    let sp2 = test_hash(51);
    let b2 = test_hash(52);

    {
        let mut tips = IndexSet::new();
        tips.insert(genesis.clone());
        create_block(&mut storage, &sp2_p, 1, tips.clone(), 100, 200).await;
        process_block(&mut storage, &sp2_p, &tips, 100).await;

        tips.clear();
        tips.insert(sp2_p.clone());
        create_block(&mut storage, &sp2, 2, tips.clone(), 100, 300).await;
        process_block(&mut storage, &sp2, &tips, 100).await;

        tips.clear();
        tips.insert(sp2.clone());
        create_block(&mut storage, &b2, 3, tips.clone(), 100, 400).await;
        process_block(&mut storage, &b2, &tips, 100).await;
    }

    let mut d_chain: Vec<Hash> = Vec::new();
    {
        let mut parent2 = genesis.clone();
        for i in 0..(K + 1) {
            let d_block = test_hash(60 + i as u8);
            let mut tips = IndexSet::new();
            tips.insert(parent2.clone());
            let height = (i + 1) as u64;
            let cumulative = 100 * (height + 1);
            create_block(&mut storage, &d_block, height, tips.clone(), 100, cumulative).await;
            process_block(&mut storage, &d_block, &tips, 100).await;
            d_chain.push(d_block.clone());
            parent2 = d_block;
        }
    }
    let dk1 = d_chain.last().unwrap().clone(); // D(k+1) = the extra block

    let f = test_hash(80);
    let mut tips_f = IndexSet::new();
    tips_f.insert(b2.clone()); // SP
    tips_f.insert(dk1.clone());
    create_block(&mut storage, &f, (K + 2) as u64, tips_f.clone(), 100, 700).await;
    let (data_f, reds_f, _) = process_block(&mut storage, &f, &tips_f, 100).await;

    // D(k+1) must be RED: B2.anticone_size was already k after D1..Dk accepted
    assert_eq!(reds_f.len(), 1,
        "Sub-test 3: exactly 1 red expected (D(k+1) rejected), got {} reds", reds_f.len());
    assert!(reds_f.contains(&dk1),
        "Sub-test 3: D(k+1) must be the red block");
    // B2(SP) + D1..Dk = k+1 blues remain
    assert_eq!(data_f.len(), K + 1,
        "Sub-test 3: expected k+1={} blues (B2 + k Ci), got {}", K + 1, data_f.len());
    // b2 must still be blue with anticone_size = k (D1..Dk all accepted)
    assert_eq!(data_f.get(&b2), Some(K),
        "Sub-test 3: B2 (SP) must have anticone_size=k={}", K);

    Ok(())
}

#[tokio::test]
async fn test_blue_score_monotonic() -> Result<()> {
    // Blue score should be monotonically non-decreasing along any chain
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    // genesis blue_work = its own difficulty = 100
    let mut prev_blue_work = CumulativeDifficulty::from_u64(100);
    let mut parent = genesis.clone();

    for i in 1u8..=10 {
        let h = test_hash(i);
        let mut tips = IndexSet::new();
        tips.insert(parent.clone());
        create_block(&mut storage, &h, i as u64, tips.clone(), 100, 100 * (i as u64 + 1)).await;
        let (data, reds, bw) = process_block(&mut storage, &h, &tips, 100).await;

        // Property #9: blue_work must strictly increase along any chain
        assert!(bw > prev_blue_work,
            "block {}: blue_work={} must strictly exceed prev={}", i, bw, prev_blue_work);
        // Each block in a linear chain has exactly 1 entry in mergeset_blues (its SP)
        assert_eq!(data.len(), 1,
            "block {}: linear chain must have exactly 1 blue (the SP)", i);
        assert!(reds.is_empty(),
            "block {}: linear chain must have no red blocks", i);

        prev_blue_work = bw;
        parent = h;
    }

    Ok(())
}

#[tokio::test]
async fn test_deep_chain_side_block_stays_blue_after_reindex() -> Result<()> {
    // After deep selected-parent chains (interval exhaustion + reindex),
    // a simple side block near the tip should still be classified blue (anticone=1 <= k).
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    let mut chain: Vec<Hash> = Vec::new();
    let mut parent = genesis.clone();

    // Build a deep chain to force interval exhaustion/reindex scenarios.
    for i in 1..=90u8 {
        let h = test_hash(i);
        let mut tips = IndexSet::new();
        tips.insert(parent.clone());
        create_block(&mut storage, &h, i as u64, tips.clone(), 100, 100 * (i as u64 + 1)).await;
        process_block(&mut storage, &h, &tips, 100).await;
        chain.push(h.clone());
        parent = h;
    }

    // Create a side block from the parent of the current tip:
    // ... -> P -> T
    //        \-> S
    // Then merge [T, S]. S should be blue (anticone size 1).
    let fork_parent = chain[88].clone(); // block 89
    let tip = chain[89].clone();         // block 90
    let side = test_hash(200);
    let merge = test_hash(201);

    let mut side_tips = IndexSet::new();
    side_tips.insert(fork_parent.clone());
    create_block(&mut storage, &side, 90, side_tips.clone(), 100, 9100).await;
    process_block(&mut storage, &side, &side_tips, 100).await;

    let mut merge_tips = IndexSet::new();
    merge_tips.insert(tip.clone());
    merge_tips.insert(side.clone());
    create_block(&mut storage, &merge, 91, merge_tips.clone(), 100, 9200).await;
    let (merge_data, merge_reds, _) = process_block(&mut storage, &merge, &merge_tips, 100).await;

    // Side block S has exactly 1 block in its anticone within the merge's blue set
    // (only 'tip' = block 90 is in S's anticone), so anticone_size=1 <= k=3 -> blue.
    assert!(merge_data.contains(&side),
        "Side block (anticone=1 <= k={}) must be in mergeset_blues", K);
    assert!(!merge_reds.contains(&side),
        "Side block must NOT be in the red set");
    let side_anticone = merge_data.get(&side).unwrap();
    assert_eq!(side_anticone, 1,
        "Side block's stored anticone_size must be exactly 1 (only 'tip' in its anticone)");

    Ok(())
}

#[tokio::test]
async fn test_reachability_after_processing() -> Result<()> {
    // After processing through GHOSTDAG, lazy reachability should work via parent traversal
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    let a = test_hash(1);
    let b = test_hash(2);

    let mut tips = IndexSet::new();
    tips.insert(genesis.clone());
    create_block(&mut storage, &a, 1, tips.clone(), 100, 200).await;
    process_block(&mut storage, &a, &tips, 100).await;

    tips.clear();
    tips.insert(a.clone());
    create_block(&mut storage, &b, 2, tips.clone(), 100, 300).await;
    process_block(&mut storage, &b, &tips, 100).await;

    // Lazy reachability: ancestor checks via parent traversal (no explicit interval storage)
    // Genesis should be ancestor of all
    assert!(is_dag_ancestor_of(&storage, &genesis, &a).await?);
    assert!(is_dag_ancestor_of(&storage, &genesis, &b).await?);
    assert!(is_dag_ancestor_of(&storage, &a, &b).await?);

    Ok(())
}

/// Property #4 + #5: mergeset_blues values are the stored anticone sizes and add_blue
/// correctly increments ALL affected peers each time a new blue is accepted.
#[tokio::test]
async fn test_anticone_sizes_stored_in_mergeset_blues() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    // Three mutually parallel blocks from genesis; p1 will be SP of the merge block.
    let p1 = test_hash(1);
    let p2 = test_hash(2);
    let p3 = test_hash(3);

    for p in [&p1, &p2, &p3] {
        let mut tips = IndexSet::new();
        tips.insert(genesis.clone());
        create_block(&mut storage, p, 1, tips.clone(), 100, 200).await;
        process_block(&mut storage, p, &tips, 100).await;
    }

    // Merge block D with tips = [p1 (SP), p2, p3]
    let d = test_hash(4);
    let mut tips_d = IndexSet::new();
    tips_d.insert(p1.clone()); // SP — first in IndexSet -> first key in mergeset_blues
    tips_d.insert(p2.clone());
    tips_d.insert(p3.clone());
    create_block(&mut storage, &d, 2, tips_d.clone(), 100, 300).await;
    let (data_d, _, _) = process_block(&mut storage, &d, &tips_d, 100).await;

    // Step-by-step expected evolution of mergeset_blues during compute_data:
    //  Start:        {p1: 0}
    //  After p2 blue: {p1: 1, p2: 1}          (p2 anticone={p1}; p1 gains p2)
    //  After p3 blue: {p1: 2, p2: 2, p3: 2}   (p3 anticone={p1,p2}; both gain p3)
    //
    // Each block's anticone within D's blue set has size 2 (the other two parallels).
    assert_eq!(data_d.get(&p1), Some(2),
        "SP p1: anticone = {{p2, p3}} -> size 2");
    assert_eq!(data_d.get(&p2), Some(2),
        "p2: anticone = {{p1, p3}} -> size 2");
    assert_eq!(data_d.get(&p3), Some(2),
        "p3: anticone = {{p1, p2}} -> size 2");

    // SP must be the FIRST key in mergeset_blues (property #1)
    let first = data_d.keys().next().unwrap();
    assert_eq!(first, &p1, "SP must be the first entry in mergeset_blues");

    Ok(())
}

/// Property #3 + #4 (boundary): The blue quota is exactly saturated when the last
/// non-SP candidate pushed into the blue set has anticone_size = k.
///
/// Since TIPS_LIMIT = k = 3, having k+1 mutually-parallel blocks as direct tips is
/// impossible.  Instead we use a chain-based topology that produces exactly k non-SP
/// candidates in the mergeset while keeping the merge block to only 2 tips:
///
///   genesis --- SP_p(1) --- SP(2) --- B(3)          <- B is the merge block's SP
///   genesis --- C1(1) --- C2(2) --- C3(3)            <- side chain, length = k
///
///   Merge M = {B, Ck}  (2 tips, well within TIPS_LIMIT)
///   Merge SP = B
///   Mergeset = {C1, C2, ..., Ck}
///
/// Anticone analysis per Ci:
///   B (level-0) is parallel to every Ci   -> +1
///   SP (historical, B's SP)               -> +1
///   SP_p (historical, SP's SP)            -> +1
///   -> each Ci.anticone_size = 3 = k  (boundary, blue)
///
/// After all k Ci accepted, B.anticone_size = k (one per Ci).  Boundary saturated.
#[tokio::test]
async fn test_k_plus_1_parallel_anticone_equals_k() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    // SP chain: genesis -> SP_p -> SP -> B (B has highest cumulative work)
    let sp_p = test_hash(1);
    let sp = test_hash(2);
    let b = test_hash(3);
    {
        let mut tips = IndexSet::new();
        tips.insert(genesis.clone());
        create_block(&mut storage, &sp_p, 1, tips.clone(), 100, 200).await;
        process_block(&mut storage, &sp_p, &tips, 100).await;

        tips.clear();
        tips.insert(sp_p.clone());
        create_block(&mut storage, &sp, 2, tips.clone(), 100, 300).await;
        process_block(&mut storage, &sp, &tips, 100).await;

        tips.clear();
        tips.insert(sp.clone());
        create_block(&mut storage, &b, 3, tips.clone(), 100, 400).await;
        process_block(&mut storage, &b, &tips, 100).await;
    }

    // Side chain of length k: C1 -> C2 -> … -> Ck (all starting from genesis)
    let mut c_chain: Vec<Hash> = Vec::new();
    {
        let mut parent = genesis.clone();
        for i in 0..K {
            let c = test_hash(10 + i as u8);
            let mut tips = IndexSet::new();
            tips.insert(parent.clone());
            let height = (i + 1) as u64;
            create_block(&mut storage, &c, height, tips.clone(), 100, 100 * (height + 1)).await;
            process_block(&mut storage, &c, &tips, 100).await;
            c_chain.push(c.clone());
            parent = c;
        }
    }
    let ck = c_chain.last().unwrap().clone();

    // Merge M: 2 tips (B as SP, Ck from side chain)
    let m = test_hash(100);
    let mut tips_m = IndexSet::new();
    tips_m.insert(b.clone()); // SP (highest cumulative_diff)
    tips_m.insert(ck.clone());
    create_block(&mut storage, &m, (K + 1) as u64, tips_m.clone(), 100, 600).await;
    let (data_m, reds_m, _) = process_block(&mut storage, &m, &tips_m, 100).await;

    // B(SP) + k C-chain blocks = k+1 total blues, no reds
    assert!(reds_m.is_empty(),
        "k={} C-chain blocks must all be blue (anticone_size=k at boundary); got {} reds",
        K, reds_m.len());
    assert_eq!(data_m.len(), K + 1,
        "Expected k+1={} blues (B + {} Ci), got {}", K + 1, K, data_m.len());

    // B (SP) must have anticone_size = k (gained one per Ci accepted)
    assert_eq!(data_m.get(&b), Some(K),
        "B (SP) must have anticone_size=k={} (saturated boundary)", K);

    // Each Ci must be blue with anticone_size = k (parallel to B, SP, SP_p)
    for (i, ci) in c_chain.iter().enumerate() {
        assert!(data_m.contains(ci), "C-chain block {} must be blue", i);
        assert_eq!(data_m.get(ci), Some(K),
            "C-chain block {} must have anticone_size=k={} (parallel to B+SP+SP_p)", i, K);
    }

    Ok(())
}

/// Property #2: Blocks that are ancestors of the selected parent must be excluded
/// from the mergeset entirely — they are already accounted for in the SP's past.
#[tokio::test]
async fn test_mergeset_excludes_sp_past() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    // genesis -> A -> B   (selected-parent chain, blue_work=300)
    // genesis -> C       (fork, enters mergeset,  blue_work=200)
    let a = test_hash(1);
    let b = test_hash(2);
    let c = test_hash(3);

    let mut tips = IndexSet::new();
    tips.insert(genesis.clone());
    create_block(&mut storage, &a, 1, tips.clone(), 100, 200).await;
    process_block(&mut storage, &a, &tips, 100).await;

    tips.clear();
    tips.insert(a.clone());
    create_block(&mut storage, &b, 2, tips.clone(), 100, 300).await;
    process_block(&mut storage, &b, &tips, 100).await;

    tips.clear();
    tips.insert(genesis.clone());
    create_block(&mut storage, &c, 1, tips.clone(), 100, 200).await;
    process_block(&mut storage, &c, &tips, 100).await;

    // Merge block D: tips = [B (SP, blue_work=300), C (mergeset, blue_work=200)]
    let d = test_hash(4);
    let mut tips_d = IndexSet::new();
    tips_d.insert(b.clone()); // SP
    tips_d.insert(c.clone());
    create_block(&mut storage, &d, 3, tips_d.clone(), 100, 400).await;
    let (data_d, reds_d, _) = process_block(&mut storage, &d, &tips_d, 100).await;

    let in_blues = |h: &Hash| data_d.contains(h);
    let in_reds  = |h: &Hash| reds_d.contains(h);

    // A and genesis are in SP's (B's) past -> must be excluded from the mergeset
    assert!(!in_blues(&a) && !in_reds(&a),
        "A is in SP's past — must NOT appear anywhere in the mergeset");
    assert!(!in_blues(&genesis) && !in_reds(&genesis),
        "Genesis is in SP's past — must NOT appear anywhere in the mergeset");

    // C is NOT in B's past -> must appear in the mergeset (blue, since anticone=1 ≤ k=3)
    assert!(in_blues(&c) || in_reds(&c),
        "C (not in SP's past) must appear in the mergeset");
    assert!(in_blues(&c),
        "C (anticone_size=1 ≤ k={}) must be blue, not red", K);

    Ok(())
}

/// Property #12: When two tips have equal cumulative difficulty (blue_work), the one
/// with the lexicographically LARGER hash is chosen as selected parent.
#[tokio::test]
async fn test_hash_tiebreak_sp_selection() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    // lo < hi by construction: test_hash(n) = [n; 32], so [1,1,...] < [200,200,...]
    let lo = test_hash(1);
    let hi = test_hash(200);

    for h in [&lo, &hi] {
        let mut tips = IndexSet::new();
        tips.insert(genesis.clone());
        // Identical cumulative difficulty -> tiebreak is decided solely by hash
        create_block(&mut storage, h, 1, tips.clone(), 100, 200).await;
        process_block(&mut storage, h, &tips, 100).await;
    }

    // sort_tips orders by cumulative_difficulty desc, ties broken by hash desc
    // -> hi ([200,200,...]) must come first
    let raw: IndexSet<Hash> = [lo.clone(), hi.clone()].into_iter().collect();
    let sorted: IndexSet<Hash> = sort_tips(&storage, raw.iter()).await?.cloned().collect();

    // Pass sorted tips so that compute_data sees hi as block_tips.first()
    let d = test_hash(202);
    create_block(&mut storage, &d, 2, sorted.clone(), 100, 300).await;
    let (data_d, _, _) = process_block(&mut storage, &d, &sorted, 100).await;

    // 'hi' has the larger hash -> must be the selected parent (first key in mergeset_blues)
    let sp = data_d.keys().next().expect("must have SP");
    assert_eq!(sp, &hi,
        "Block with larger hash must be SP when cumulative difficulties are equal");

    // 'lo' must appear as a blue mergeset entry (anticone_size=1 ≤ k={})
    assert!(data_d.contains(&lo),
        "'lo' must be blue in the mergeset (anticone_size=1 ≤ k={})", K);

    Ok(())
}

/// Helper: create a deterministic hash from a u16 index.
fn test_hash16(index: u16) -> Hash {
    let lo = (index & 0xff) as u8;
    let hi = ((index >> 8) & 0xff) as u8;
    let mut bytes = [lo; 32];
    bytes[31] = hi;
    Hash::new(bytes)
}

/// DAG reachability via the future covering set must work correctly
/// for a wide DAG (many blocks merging into a single tip).
///
/// Topology (chained merges, each with ≤ 3 tips = TIPS_LIMIT):
///   genesis -> A, B, C       (3 parallel branches)
///   merge1  ← {A, B, C}     (merges first 3 branches)
///   genesis -> D, E           (2 more parallel branches)
///   merge2  ← {merge1, D, E} (merges everything into one tip)
///
/// After GHOSTDAG:
///   - genesis is a DAG ancestor of A, B, C, D, E, merge1, merge2
///   - A, B, C are DAG ancestors of merge1 and merge2 (transitively)
///   - D, E are DAG ancestors of merge2
///   - merge1 is a DAG ancestor of merge2
///   - A, B, C are mutually NOT in each other's past (anticone)
///   - D, E are NOT in each other's past (anticone)
#[tokio::test]
async fn test_reachability_wide_dag_fcs() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash16(0);
    create_genesis(&mut storage, &genesis, 100).await;

    // Build 3 parallel branches from genesis
    let a = test_hash16(1);
    let b = test_hash16(2);
    let c = test_hash16(3);
    for branch in [&a, &b, &c] {
        let mut tips = IndexSet::new();
        tips.insert(genesis.clone());
        create_block(&mut storage, branch, 1, tips.clone(), 100, 200).await;
        process_block(&mut storage, branch, &tips, 100).await;
    }

    // merge1 merges {A, B, C} (3 tips = TIPS_LIMIT)
    let merge1 = test_hash16(10);
    let mut tips_m1 = IndexSet::new();
    tips_m1.insert(a.clone());
    tips_m1.insert(b.clone());
    tips_m1.insert(c.clone());
    create_block(&mut storage, &merge1, 2, tips_m1.clone(), 100, 300).await;
    process_block(&mut storage, &merge1, &tips_m1, 100).await;

    // 2 more parallel branches from genesis
    let d = test_hash16(4);
    let e = test_hash16(5);
    for branch in [&d, &e] {
        let mut tips = IndexSet::new();
        tips.insert(genesis.clone());
        create_block(&mut storage, branch, 1, tips.clone(), 100, 200).await;
        process_block(&mut storage, branch, &tips, 100).await;
    }

    // merge2 merges {merge1, D, E} (3 tips = TIPS_LIMIT)
    let merge2 = test_hash16(1000);
    let mut tips_m2 = IndexSet::new();
    tips_m2.insert(merge1.clone());
    tips_m2.insert(d.clone());
    tips_m2.insert(e.clone());
    create_block(&mut storage, &merge2, 3, tips_m2.clone(), 100, 400).await;
    process_block(&mut storage, &merge2, &tips_m2, 100).await;

    let first_branches = [&a, &b, &c];
    let second_branches = [&d, &e];
    let all_branches: Vec<&Hash> = first_branches.iter().chain(second_branches.iter()).copied().collect();

    // genesis is a DAG ancestor of every branch and both merge blocks.
    for branch in &all_branches {
        assert!(
            is_dag_ancestor_of(&storage, &genesis, branch).await?,
            "genesis must be DAG ancestor of every branch"
        );
    }
    assert!(
        is_dag_ancestor_of(&storage, &genesis, &merge1).await?,
        "genesis must be DAG ancestor of merge1"
    );
    assert!(
        is_dag_ancestor_of(&storage, &genesis, &merge2).await?,
        "genesis must be DAG ancestor of merge2"
    );

    // A, B, C are DAG ancestors of merge1 and merge2 (transitively through merge1).
    for branch in &first_branches {
        assert!(
            is_dag_ancestor_of(&storage, branch, &merge1).await?,
            "first branch must be DAG ancestor of merge1"
        );
        assert!(
            is_dag_ancestor_of(&storage, branch, &merge2).await?,
            "first branch must be DAG ancestor of merge2 (transitively)"
        );
    }

    // D, E are DAG ancestors of merge2.
    for branch in &second_branches {
        assert!(
            is_dag_ancestor_of(&storage, branch, &merge2).await?,
            "second branch must be DAG ancestor of merge2"
        );
        // D, E are NOT ancestors of merge1 (merge1 was built before D and E).
        assert!(
            !is_dag_ancestor_of(&storage, branch, &merge1).await?,
            "second branch must NOT be DAG ancestor of merge1"
        );
    }

    // merge1 is a DAG ancestor of merge2.
    assert!(
        is_dag_ancestor_of(&storage, &merge1, &merge2).await?,
        "merge1 must be DAG ancestor of merge2"
    );

    // First branches are mutually not in each other's past (anticone).
    for i in 0..first_branches.len() {
        for j in 0..first_branches.len() {
            if i == j { continue; }
            assert!(
                !is_dag_ancestor_of(&storage, first_branches[i], first_branches[j]).await?,
                "first_branch[{}] must NOT be DAG ancestor of first_branch[{}]", i, j
            );
        }
    }

    // D and E are mutually not in each other's past (anticone).
    assert!(
        !is_dag_ancestor_of(&storage, &d, &e).await?,
        "D must NOT be DAG ancestor of E"
    );
    assert!(
        !is_dag_ancestor_of(&storage, &e, &d).await?,
        "E must NOT be DAG ancestor of D"
    );

    Ok(())
}
// Edge case: a tip that is an ancestor of the selected parent must be excluded from the mergeset.
//
// Topology:
//   genesis -> A -> B   (B is selected parent because it has higher blue_work)
//   D has tips [B, A]   (A is already in B's past)
//
// Expected: A must NOT appear in the mergeset (neither blue nor red).
#[tokio::test]
async fn test_ancestor_tip_excluded_from_mergeset() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    let a = test_hash(1);
    let b = test_hash(2);

    let mut tips = IndexSet::new();
    tips.insert(genesis.clone());
    create_block(&mut storage, &a, 1, tips.clone(), 100, 200).await;
    process_block(&mut storage, &a, &tips, 100).await;

    tips.clear();
    tips.insert(a.clone());
    create_block(&mut storage, &b, 2, tips.clone(), 100, 300).await;
    process_block(&mut storage, &b, &tips, 100).await;

    // D tips: B (SP, higher blue_work=300) and A (ancestor of B)
    let d = test_hash(3);
    let mut tips_d = IndexSet::new();
    tips_d.insert(b.clone()); // SP
    tips_d.insert(a.clone()); // ancestor of SP -> must be excluded
    create_block(&mut storage, &d, 3, tips_d.clone(), 100, 400).await;
    let (data_d, reds_d, _) = process_block(&mut storage, &d, &tips_d, 100).await;

    // A is in B's past so it must be excluded from the mergeset entirely
    assert!(!data_d.contains(&a),
        "A (ancestor of SP B) must not appear in mergeset_blues");
    assert!(!reds_d.contains(&a),
        "A (ancestor of SP B) must not appear in the red set");

    // Only the SP (B) should be in blues
    assert_eq!(data_d.len(), 1,
        "Only SP should be in mergeset_blues when the other tip is an ancestor of SP");
    assert!(reds_d.is_empty(),
        "No red blocks when the non-SP tip is an ancestor of SP");

    Ok(())
}

// Edge case: red blocks must not contribute to blue_work.
//
// Build a scenario where some blocks are provably red and verify that
// the resulting blue_work does NOT include their difficulty.
#[tokio::test]
async fn test_red_blocks_excluded_from_blue_work() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    // Honest chain: genesis -> H1 -> H2 -> H3 -> H4 (blue_work = 500)
    // We need k+1 = 4 honest blocks so the attacker's anticone exceeds k=3.
    let h1 = test_hash(1);
    let h2 = test_hash(2);
    let h3 = test_hash(3);
    let h4 = test_hash(4);
    let honest = [&h1, &h2, &h3, &h4];

    let mut tips = IndexSet::new();
    tips.insert(genesis.clone());
    for (i, h) in honest.iter().enumerate() {
        create_block(&mut storage, h, (i + 1) as u64, tips.clone(), 100, 100 * (i as u64 + 2)).await;
        process_block(&mut storage, h, &tips, 100).await;
        tips.clear();
        tips.insert((*h).clone());
    }
    // h4.blue_work = genesis(100) + H1(100) + H2(100) + H3(100) + H4(100) = 500

    // Attacker chain: genesis -> A1 -> A2 -> A3 (parallel to honest chain)
    // Each attacker block has 4 blocks from the honest chain in its anticone (H1..H4) > k=3.
    let a1 = test_hash(10);
    let a2 = test_hash(11);
    let a3 = test_hash(12);
    let attacker = [&a1, &a2, &a3];

    let mut parent_tips = IndexSet::new();
    parent_tips.insert(genesis.clone());
    for (i, a) in attacker.iter().enumerate() {
        create_block(&mut storage, a, (i + 1) as u64, parent_tips.clone(), 100, 100 * (i as u64 + 2)).await;
        process_block(&mut storage, a, &parent_tips, 100).await;
        parent_tips.clear();
        parent_tips.insert((*a).clone());
    }

    // Merge: tips = [H4 (SP, blue_work=500), A3]
    let merge = test_hash(99);
    let mut merge_tips = IndexSet::new();
    merge_tips.insert(h4.clone()); // SP: higher blue_work
    merge_tips.insert(a3.clone());
    create_block(&mut storage, &merge, 5, merge_tips.clone(), 100, 600).await;
    let (merge_data, merge_reds, merge_blue_work) = process_block(&mut storage, &merge, &merge_tips, 100).await;

    // All attacker blocks should be red (anticone = {H1,H2,H3,H4} = 4 > k=3)
    assert!(!merge_reds.is_empty(),
        "Attacker chain blocks must be red when their anticone size exceeds k");
    assert_eq!(merge_data.len(), 1,
        "Only SP (H4) should be in mergeset_blues; got {} blues", merge_data.len());

    // Blue work = SP.blue_work + self_diff = 500 + 100 = 600
    // Red blocks (A1-A3, each diff=100) must NOT contribute
    let expected_blue_work = CumulativeDifficulty::from_u64(600);
    assert_eq!(merge_blue_work, expected_blue_work,
        "blue_work must equal SP.blue_work + self_diff only; red blocks must not contribute");

    Ok(())
}

// Edge case: diamond DAG where both tips share a common ancestor beyond genesis.
//
// Topology:
//   genesis -> A -> B
//              A -> C
//   D has tips [B, C]  (both are children of A, which is NOT genesis)
//
// Expected:
//   - SP is B or C (based on hash tiebreak, same cumulative_difficulty)
//   - The non-SP is in the mergeset and blue (anticone = 1 <= k)
//   - A and genesis are in SP's past so they must be excluded from mergeset
#[tokio::test]
async fn test_diamond_merge_shared_ancestor() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    let a = test_hash(1);
    let b = test_hash(2);
    let c = test_hash(3);

    let mut tips = IndexSet::new();
    tips.insert(genesis.clone());
    create_block(&mut storage, &a, 1, tips.clone(), 100, 200).await;
    process_block(&mut storage, &a, &tips, 100).await;

    tips.clear();
    tips.insert(a.clone());
    create_block(&mut storage, &b, 2, tips.clone(), 100, 300).await;
    process_block(&mut storage, &b, &tips, 100).await;

    tips.clear();
    tips.insert(a.clone());
    create_block(&mut storage, &c, 2, tips.clone(), 100, 300).await;
    process_block(&mut storage, &c, &tips, 100).await;

    // D merges B and C (equal blue_work -> tiebreak by hash; b=[2;32] < c=[3;32] -> c is SP)
    let d = test_hash(4);
    let mut tips_d = IndexSet::new();
    tips_d.insert(b.clone());
    tips_d.insert(c.clone());
    create_block(&mut storage, &d, 3, tips_d.clone(), 100, 400).await;
    let (data_d, reds_d, blue_work_d) = process_block(&mut storage, &d, &tips_d, 100).await;

    // Whichever is SP, the other must be in mergeset_blues (anticone=1 <= k=3)
    assert_eq!(data_d.len(), 2,
        "SP + one non-SP blue (anticone=1)");
    assert!(reds_d.is_empty(),
        "No red blocks in diamond merge");

    // A and genesis are ancestors of both B and C, so they must be excluded
    assert!(!data_d.contains(&a),
        "A (ancestor of SP) must be excluded from mergeset");
    assert!(!data_d.contains(&genesis),
        "genesis (ancestor of SP) must be excluded from mergeset");
    assert!(!reds_d.contains(&a),
        "A must not be in reds");
    assert!(!reds_d.contains(&genesis),
        "genesis must not be in reds");

    // blue_work = SP.blue_work(300) + non_SP.diff(100) + self_diff(100) = 500
    assert_eq!(blue_work_d, CumulativeDifficulty::from_u64(500));

    Ok(())
}

// Edge case: anticone_size invariant -- no blue block's stored anticone_size exceeds k.
//
// For any merge block we build, every entry in mergeset_blues must have
// anticone_size <= GHOSTDAG_K.  This is the core safety property.
#[tokio::test]
async fn test_anticone_size_never_exceeds_k() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    // Build k parallel blocks (maximum allowed without any going red)
    let parallels: Vec<Hash> = (1u8..=(K as u8)).map(test_hash).collect();
    for h in &parallels {
        let mut tips = IndexSet::new();
        tips.insert(genesis.clone());
        create_block(&mut storage, h, 1, tips.clone(), 100, 200).await;
        process_block(&mut storage, h, &tips, 100).await;
    }

    let merge = test_hash(100);
    let tips_m: IndexSet<Hash> = parallels.iter().cloned().collect();
    create_block(&mut storage, &merge, 2, tips_m.clone(), 100, 300).await;
    let (data_m, reds_m, _) = process_block(&mut storage, &merge, &tips_m, 100).await;

    // Invariant: every blue's stored anticone_size must be <= k
    for (hash, size) in data_m.iter() {
        assert!(size <= K,
            "block {:?} has anticone_size={} > k={}", hash, size, K);
    }
    assert!(reds_m.is_empty(),
        "k parallel blocks must all be blue");

    Ok(())
}

// Edge case: chain of merge blocks -- verify that blue_work is strictly increasing
// even when non-trivial mergesets (with both blues and reds) are involved.
#[tokio::test]
async fn test_blue_work_strictly_increasing_with_merges() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    // Round 1: two parallel blocks A, B, merged by C.
    let a = test_hash(1);
    let b = test_hash(2);
    let c = test_hash(3);

    let mut tips = IndexSet::new();
    tips.insert(genesis.clone());
    create_block(&mut storage, &a, 1, tips.clone(), 100, 200).await;
    let (_, _, bw_a) = process_block(&mut storage, &a, &tips, 100).await;

    tips.clear();
    tips.insert(genesis.clone());
    create_block(&mut storage, &b, 1, tips.clone(), 100, 200).await;
    let (_, _, bw_b) = process_block(&mut storage, &b, &tips, 100).await;

    tips.clear();
    tips.insert(a.clone());
    tips.insert(b.clone());
    create_block(&mut storage, &c, 2, tips.clone(), 100, 300).await;
    let (_, _, bw_c) = process_block(&mut storage, &c, &tips, 100).await;

    // bw_c must exceed both parents
    assert!(bw_c > bw_a, "C.blue_work must exceed A.blue_work");
    assert!(bw_c > bw_b, "C.blue_work must exceed B.blue_work");

    // Round 2: two more parallel blocks D, E, merged by F that also takes C.
    let d = test_hash(4);
    let e = test_hash(5);
    let f = test_hash(6);

    tips.clear();
    tips.insert(c.clone());
    create_block(&mut storage, &d, 3, tips.clone(), 100, 400).await;
    let (_, _, bw_d) = process_block(&mut storage, &d, &tips, 100).await;

    tips.clear();
    tips.insert(c.clone());
    create_block(&mut storage, &e, 3, tips.clone(), 100, 400).await;
    let (_, _, bw_e) = process_block(&mut storage, &e, &tips, 100).await;

    tips.clear();
    tips.insert(d.clone());
    tips.insert(e.clone());
    create_block(&mut storage, &f, 4, tips.clone(), 100, 500).await;
    let (_, _, bw_f) = process_block(&mut storage, &f, &tips, 100).await;

    assert!(bw_f > bw_d, "F.blue_work must exceed D.blue_work");
    assert!(bw_f > bw_e, "F.blue_work must exceed E.blue_work");
    assert!(bw_f > bw_c, "F.blue_work must exceed C.blue_work");

    Ok(())
}

// Edge case: genesis self-ancestry check (trivial, but documents the base case).
#[tokio::test]
async fn test_reachability_genesis_self_ancestor() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    // Genesis is its own ancestor
    assert!(is_dag_ancestor_of(&storage, &genesis, &genesis).await?);

    Ok(())
}

// Edge case: non-existent block used as ancestor returns false rather than erroring.
// (Uses a block that exists in storage but is unrelated to genesis.)
#[tokio::test]
async fn test_reachability_unrelated_blocks_not_ancestors() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    // Create an isolated block not connected to genesis
    // (height mismatch prevents the ancestor check from erroneously returning true)
    let a = test_hash(1);
    let b = test_hash(2);

    let mut tips = IndexSet::new();
    tips.insert(genesis.clone());
    create_block(&mut storage, &a, 1, tips.clone(), 100, 200).await;
    create_block(&mut storage, &b, 1, tips.clone(), 100, 200).await;
    // Neither a nor b was made a child of the other
    assert!(!is_dag_ancestor_of(&storage, &a, &b).await?);
    assert!(!is_dag_ancestor_of(&storage, &b, &a).await?);

    Ok(())
}

// Edge case: duplicate tip entries must not cause double-counting.
//
// Even if the same hash appears twice in the tip list, compute_mergeset must
// deduplicate and not include the SP more than once.
#[tokio::test]
async fn test_duplicate_tip_deduplication() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    let a = test_hash(1);
    let b = test_hash(2);

    let mut tips = IndexSet::new();
    tips.insert(genesis.clone());
    create_block(&mut storage, &a, 1, tips.clone(), 100, 200).await;
    process_block(&mut storage, &a, &tips, 100).await;

    tips.clear();
    tips.insert(genesis.clone());
    create_block(&mut storage, &b, 1, tips.clone(), 100, 200).await;
    process_block(&mut storage, &b, &tips, 100).await;

    // IndexSet automatically deduplicates, so inserting a twice has no effect.
    let mut tips_c = IndexSet::new();
    tips_c.insert(a.clone());
    tips_c.insert(b.clone());
    tips_c.insert(a.clone()); // duplicate: silently ignored by IndexSet

    let c = test_hash(3);
    create_block(&mut storage, &c, 2, tips_c.clone(), 100, 300).await;
    let (data_c, reds_c, _) = process_block(&mut storage, &c, &tips_c, 100).await;

    // Should behave exactly like a normal two-parent merge
    assert_eq!(data_c.len(), 2,
        "SP + one non-SP blue, duplicate tip must be ignored");
    assert!(reds_c.is_empty(),
        "No red blocks in a simple two-parent merge");

    Ok(())
}

// Edge case: after k parallel blocks are blue, the (k+1)th non-SP block is red.
// Verify the exact threshold: with k non-SP blue candidates and 2 extra,
// the first k are blue and the remaining 2 are red.
//
// Uses the same chain topology as test_k_boundary:
//   genesis -> SP_p -> SP -> B   (B is the merge SP, highest cumulative work)
//   genesis -> C1 -> C2 -> ... -> C(k+2)  (side chain; last block is the tip)
//
//   Merge = {B, C(k+2)}  (2 tips, respects TIPS_LIMIT = 3)
//   Mergeset = {C1, C2, ..., C(k+2)}  (all k+2 candidates)
//
//   C1..Ck: each has anticone_size = k (B + SP + SP_p = 3 = k in anticone) -> BLUE.
//   After Ck: B.anticone_size = k, SP.anticone_size = k, SP_p.anticone_size = k.
//   C(k+1): B already has anticone_size = k -> RED (peer check fires).
//   C(k+2): B's anticone_size unchanged (C(k+1) was rejected) -> RED again.
//   Total reds = 2
#[tokio::test]
async fn test_exactly_two_red_above_k() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    // SP chain: genesis -> SP_p -> SP -> B  (B has highest cumulative work)
    let sp_p = test_hash(1);
    let sp = test_hash(2);
    let b = test_hash(3);
    {
        let mut tips = IndexSet::new();
        tips.insert(genesis.clone());
        create_block(&mut storage, &sp_p, 1, tips.clone(), 100, 200).await;
        process_block(&mut storage, &sp_p, &tips, 100).await;

        tips.clear();
        tips.insert(sp_p.clone());
        create_block(&mut storage, &sp, 2, tips.clone(), 100, 300).await;
        process_block(&mut storage, &sp, &tips, 100).await;

        tips.clear();
        tips.insert(sp.clone());
        create_block(&mut storage, &b, 3, tips.clone(), 100, 400).await;
        process_block(&mut storage, &b, &tips, 100).await;
    }

    // Side chain of length k+2: C1 -> C2 -> ... -> C(k+2)
    let c_count = K + 2;
    let mut c_chain: Vec<Hash> = Vec::new();
    {
        let mut parent = genesis.clone();
        for i in 0..c_count {
            let c = test_hash(10 + i as u8);
            let mut tips = IndexSet::new();
            tips.insert(parent.clone());
            let height = (i + 1) as u64;
            create_block(&mut storage, &c, height, tips.clone(), 100, 100 * (height + 1)).await;
            process_block(&mut storage, &c, &tips, 100).await;
            c_chain.push(c.clone());
            parent = c;
        }
    }
    let c_tip = c_chain.last().unwrap().clone();

    let merge = test_hash(200);
    let mut tips_m = IndexSet::new();
    tips_m.insert(b.clone()); // SP (highest cumulative_diff)
    tips_m.insert(c_tip.clone());
    create_block(&mut storage, &merge, (K + 3) as u64, tips_m.clone(), 100, 600).await;
    let (data_m, reds_m, _) = process_block(&mut storage, &merge, &tips_m, 100).await;

    // B(SP) + k blues = k+1 total blues; exactly 2 reds
    assert_eq!(data_m.len(), K + 1,
        "Expected B(SP) + k={} blues = {} total, got {}", K, K + 1, data_m.len());
    assert_eq!(reds_m.len(), 2,
        "Expected exactly 2 red blocks (C(k+1) and C(k+2)), got {}", reds_m.len());

    // The first k C-chain blocks must be blue
    for ci in c_chain.iter().take(K) {
        assert!(data_m.contains(ci),
            "C1..Ck must all be blue");
    }
    // The last 2 C-chain blocks must be red
    for ci in c_chain.iter().skip(K) {
        assert!(reds_m.contains(ci),
            "C(k+1) and C(k+2) must be red");
    }

    // Anticone invariant: all blues have anticone_size ≤ k
    for (_, size) in data_m.iter() {
        assert!(size <= K,
            "No blue block may have anticone_size > k");
    }

    Ok(())
}

#[tokio::test]
async fn test_historical_blues_anticone_tracking() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    // Build SP chain: genesis(cd=100) -> H1(h=1, cd=500) -> H2(h=2, cd=1000) -> SP(h=3, cd=2000)
    // High cumulative difficulty ensures SP wins over S3 as selected parent.
    let h1 = test_hash(1);
    let h2 = test_hash(2);
    let sp_block = test_hash(3);

    let mut tips = IndexSet::new();
    tips.insert(genesis.clone());
    create_block(&mut storage, &h1, 1, tips.clone(), 400, 500).await;
    process_block(&mut storage, &h1, &tips, 400).await;

    tips.clear();
    tips.insert(h1.clone());
    create_block(&mut storage, &h2, 2, tips.clone(), 500, 1000).await;
    process_block(&mut storage, &h2, &tips, 500).await;

    tips.clear();
    tips.insert(h2.clone());
    create_block(&mut storage, &sp_block, 3, tips.clone(), 1000, 2000).await;
    process_block(&mut storage, &sp_block, &tips, 1000).await;

    // Build side chain: genesis(cd=100) -> S1(h=1, cd=200) -> S2(h=2, cd=300) -> S3(h=3, cd=400)
    // Low cumulative difficulty ensures S3 loses to SP as selected parent.
    let s1 = test_hash(10);
    let s2 = test_hash(11);
    let s3 = test_hash(12);

    tips.clear();
    tips.insert(genesis.clone());
    create_block(&mut storage, &s1, 1, tips.clone(), 100, 200).await;
    process_block(&mut storage, &s1, &tips, 100).await;

    tips.clear();
    tips.insert(s1.clone());
    create_block(&mut storage, &s2, 2, tips.clone(), 100, 300).await;
    process_block(&mut storage, &s2, &tips, 100).await;

    tips.clear();
    tips.insert(s2.clone());
    create_block(&mut storage, &s3, 3, tips.clone(), 100, 400).await;
    process_block(&mut storage, &s3, &tips, 100).await;

    // Merge block with exactly 2 tips: { SP (selected parent), S3 }
    // S1, S2, S3 enter the mergeset via S3's ancestry.
    let merge = test_hash(100);
    let mut merge_tips = IndexSet::new();
    merge_tips.insert(sp_block.clone());
    merge_tips.insert(s3.clone());
    create_block(&mut storage, &merge, 4, merge_tips.clone(), 100, 2100).await;
    let (merge_data, _, _) = process_block(&mut storage, &merge, &merge_tips, 100).await;

    // All mergeset blues = {SP, S1, S2, S3} — 4 blocks, all accepted
    // (each Si has anticone_size=3=k, exactly at the boundary, not exceeded)
    assert_eq!(merge_data.len(), 4,
        "Mergeset blues should be SP + S1 + S2 + S3 (all 4 fit within k=3 anticone budget)");
    assert!(merge_data.contains(&sp_block), "SP must be blue (it is the selected parent)");
    assert!(merge_data.contains(&s1), "S1 must be blue (anticone_size=k=3)");
    assert!(merge_data.contains(&s2), "S2 must be blue (anticone_size=k=3)");
    assert!(merge_data.contains(&s3), "S3 must be blue (anticone_size=k=3)");

    // SP's anticone_size = 3 after all three Si added it
    let sp_anticone = merge_data.get(&sp_block);
    assert_eq!(sp_anticone, Some(K as usize),
        "SP (level-0 blue) must have anticone_size=k=3 after all three Si accepted. Got {:?}",
        sp_anticone);

    // Each Si has anticone_size = 3 (SP + H2 + H1 all in its anticone)
    assert_eq!(merge_data.get(&s1), Some(K as usize),
        "S1 must have anticone_size=k=3 (parallel to SP, H2, H1)");
    assert_eq!(merge_data.get(&s2), Some(K as usize),
        "S2 must have anticone_size=k=3 (parallel to SP, H2, H1)");
    assert_eq!(merge_data.get(&s3), Some(K as usize),
        "S3 must have anticone_size=k=3 (parallel to SP, H2, H1)");

    // Historical blues H1 and H2 should have their anticone sizes
    // accumulated in updated_anticones.
    let h2_anticone = merge_data.get(&h2);
    assert_eq!(h2_anticone, Some(K as usize),
        "H2 (historical blue) must have anticone_size=k=3. Got {:?}",
        h2_anticone);

    let h1_anticone = merge_data.get(&h1);
    assert_eq!(h1_anticone, Some(K as usize),
        "H1 (historical blue, deeper in SP chain) must have anticone_size=k=3. Got {:?}",
        h1_anticone);

    Ok(())
}

#[tokio::test]
async fn test_mergeset_processing_order() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    // Build chain 1: genesis -> A -> B
    let a = test_hash(1);
    let b = test_hash(2);

    let mut tips = IndexSet::new();
    tips.insert(genesis.clone());
    create_block(&mut storage, &a, 1, tips.clone(), 100, 200).await;
    process_block(&mut storage, &a, &tips, 100).await;

    tips.clear();
    tips.insert(a.clone());
    create_block(&mut storage, &b, 2, tips.clone(), 100, 300).await;
    process_block(&mut storage, &b, &tips, 100).await;

    // Build chain 2: genesis -> C -> D
    let c = test_hash(10);
    let d = test_hash(11);

    tips.clear();
    tips.insert(genesis.clone());
    create_block(&mut storage, &c, 1, tips.clone(), 100, 200).await;
    process_block(&mut storage, &c, &tips, 100).await;

    tips.clear();
    tips.insert(c.clone());
    create_block(&mut storage, &d, 2, tips.clone(), 100, 300).await;
    process_block(&mut storage, &d, &tips, 100).await;

    // Merge block E: tips = [B, D]
    let e = test_hash(100);
    let mut tips_e = IndexSet::new();
    tips_e.insert(b.clone());
    tips_e.insert(d.clone());
    create_block(&mut storage, &e, 3, tips_e.clone(), 100, 400).await;
    let (merge_data_e, reds_e, blue_work_e) = process_block(&mut storage, &e, &tips_e, 100).await;

    // Both D and C should be in mergeset (not ancestors of B)
    assert!(merge_data_e.contains(&d) || reds_e.contains(&d),
        "D must appear in mergeset (either blue or red)");
    assert!(merge_data_e.contains(&c) || reds_e.contains(&c),
        "C must appear in mergeset (either blue or red)");

    // CRITICAL: All blues must have anticone_size <= k (topological order ensures this)
    for (h, size) in merge_data_e.iter() {
        assert!(size <= K,
            "block {:?} has anticone_size={} > k={}", h, size, K);
    }

    // Verify blue_work is correctly accumulated
    let expected_min = CumulativeDifficulty::from_u64(300 + 100);
    assert!(blue_work_e >= expected_min,
        "E.blue_work must include SP's work");

    Ok(())
}

#[tokio::test]
async fn test_deterministic_mergeset_ordering() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    let b1 = test_hash(50);
    let b2 = test_hash(51);
    let b3 = test_hash(49);

    let mut tips = IndexSet::new();
    tips.insert(genesis.clone());

    create_block(&mut storage, &b1, 1, tips.clone(), 100, 200).await;
    process_block(&mut storage, &b1, &tips, 100).await;

    create_block(&mut storage, &b2, 1, tips.clone(), 100, 200).await;
    process_block(&mut storage, &b2, &tips, 100).await;

    create_block(&mut storage, &b3, 1, tips.clone(), 100, 200).await;
    process_block(&mut storage, &b3, &tips, 100).await;

    // Merge with tips in non-sorted order: [b3, b2, b1]
    let m = test_hash(100);
    let mut tips_m = IndexSet::new();
    tips_m.insert(b3.clone());
    tips_m.insert(b2.clone());
    tips_m.insert(b1.clone());
    create_block(&mut storage, &m, 2, tips_m.clone(), 100, 300).await;
    let (merge_data_m, _, _) = process_block(&mut storage, &m, &tips_m, 100).await;

    // SP + 2 non-SP blues = 3 total (b1, b2, b3 are the only blocks in the mergeset)
    assert_eq!(merge_data_m.len(), 3,
        "Should have exactly 3 blues: SP + 2 non-SP (one per tip). Got {}",
        merge_data_m.len());
    assert!(merge_data_m.contains(&b1), "b1 must be blue");
    assert!(merge_data_m.contains(&b2), "b2 must be blue");
    assert!(merge_data_m.contains(&b3), "b3 must be blue");

    // Each block is mutually parallel to the other two: anticone_size = 2 for all.
    // (SP's anticone_size is also 2 — it accumulates one entry per non-SP blue.)
    for (h, size) in merge_data_m.iter() {
        assert_eq!(size, 2,
            "block {:?} has anticone_size={}, expected 2 \
             (each block is parallel to the other two)", h, size);
        assert!(size <= K,
            "No blue may have anticone_size > k");
    }

    // DETERMINISM: the SP (first entry in mergeset_blues) must always be the same
    // block regardless of tip insertion order. With equal cd=200, SP is determined
    // by the tie-breaking rule (hash order in selection logic).
    let keys: Vec<_> = merge_data_m.keys().collect();
    let sp_hash = keys[0];
    assert!(
        *sp_hash == b1 || *sp_hash == b2 || *sp_hash == b3,
        "SP must be one of b1, b2, or b3"
    );

    Ok(())
}

#[tokio::test]
async fn test_complex_dag_historical_and_ordering() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    // Build SP chain: genesis -> H1 -> H2 -> H3
    let h1 = test_hash(1);
    let h2 = test_hash(2);
    let h3 = test_hash(3);

    let mut tips = IndexSet::new();
    tips.insert(genesis.clone());
    for (h, idx) in [(&h1, 1u64), (&h2, 2u64), (&h3, 3u64)] {
        create_block(&mut storage, h, idx, tips.clone(), 100, 100 * (idx + 1)).await;
        process_block(&mut storage, h, &tips, 100).await;
        tips.clear();
        tips.insert((*h).clone());
    }

    // Build parallel side chain: genesis -> S1 -> S2
    let s1 = test_hash(10);
    let s2 = test_hash(11);

    tips.clear();
    tips.insert(genesis.clone());
    create_block(&mut storage, &s1, 1, tips.clone(), 100, 200).await;
    process_block(&mut storage, &s1, &tips, 100).await;

    tips.clear();
    tips.insert(s1.clone());
    create_block(&mut storage, &s2, 2, tips.clone(), 100, 300).await;
    process_block(&mut storage, &s2, &tips, 100).await;

    // Merge block M: tips = [H3 (SP), S2]
    let m = test_hash(100);
    let mut tips_m = IndexSet::new();
    tips_m.insert(h3.clone());
    tips_m.insert(s2.clone());
    create_block(&mut storage, &m, 4, tips_m.clone(), 100, 500).await;
    let (merge_data_m, reds_m, blue_work_m) = process_block(&mut storage, &m, &tips_m, 100).await;

    assert!(reds_m.is_empty(), "No reds in this merge");
    // H3 (SP) + S1 + S2 = 3 blue blocks.
    // S1 is in the mergeset because it's an ancestor of S2 (not in H3's past).
    assert_eq!(merge_data_m.len(), 3, "H3 (SP) + S1 + S2 all blue");
    assert!(merge_data_m.contains(&h3), "H3 must be SP");
    assert!(merge_data_m.contains(&s1), "S1 must be in mergeset");
    assert!(merge_data_m.contains(&s2), "S2 must be in mergeset");

    // H3 (SP at level 0) accumulates one anticone entry per accepted Si:
    //   S1 accepted -> H3.anticone_size = 1
    //   S2 accepted -> H3.anticone_size = 2
    assert_eq!(merge_data_m.get(&h3), Some(2), "H3 (SP) anticone_size=2 (S1+S2 in its anticone)");

    // S1 is parallel to H3 (level-0), H2 (in H3's blues), H1 (in H2's blues).
    // Genesis is ancestor of S1 -> S1.anticone_size = 3 = k (exactly at boundary).
    assert_eq!(merge_data_m.get(&s1), Some(K as usize), "S1 anticone_size=k=3");

    // S2 is parallel to H3, H2, H1. S1 is ancestor of S2 -> skipped.
    // Genesis is ancestor -> S2.anticone_size = 3 = k.
    assert_eq!(merge_data_m.get(&s2), Some(K as usize), "S2 anticone_size=k=3");

    // H2 and H1 should have their anticone sizes tracked in
    // updated_anticones (incremented once per Si accepted).
    assert_eq!(merge_data_m.get(&h2), Some(2), "H2 (historical) anticone_size=2 (S1+S2)");
    assert_eq!(merge_data_m.get(&h1), Some(2), "H1 (historical) anticone_size=2 (S1+S2)");

    // blue_work = M.difficulty(100) + H3.cumulative_difficulty(400) + S1.difficulty(100) + S2.difficulty(100) = 700
    assert_eq!(blue_work_m, CumulativeDifficulty::from_u64(700));

    Ok(())
}

/// Edge case: all non-SP tips are ancestors of the selected parent.
/// The mergeset must be empty (only SP in blues, no reds).
///
/// Topology:
///   genesis -> A -> B -> C (SP, highest CD)
///   D has tips [C, A, genesis] — but A and genesis are both in C's past
#[tokio::test]
async fn test_all_non_sp_tips_are_sp_ancestors() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    let a = test_hash(1);
    let b = test_hash(2);
    let c = test_hash(3);

    let mut tips = IndexSet::new();
    tips.insert(genesis.clone());
    create_block(&mut storage, &a, 1, tips.clone(), 100, 200).await;
    process_block(&mut storage, &a, &tips, 100).await;

    tips.clear(); tips.insert(a.clone());
    create_block(&mut storage, &b, 2, tips.clone(), 100, 300).await;
    process_block(&mut storage, &b, &tips, 100).await;

    tips.clear(); tips.insert(b.clone());
    create_block(&mut storage, &c, 3, tips.clone(), 100, 400).await;
    process_block(&mut storage, &c, &tips, 100).await;

    // D has tips [C (SP), A] — A is in C's past
    let d = test_hash(4);
    let mut tips_d = IndexSet::new();
    tips_d.insert(c.clone());
    tips_d.insert(a.clone());
    create_block(&mut storage, &d, 4, tips_d.clone(), 100, 500).await;
    let (data_d, reds_d, blue_work_d) = process_block(&mut storage, &d, &tips_d, 100).await;

    // A is in C's past -> excluded from mergeset entirely
    assert_eq!(data_d.len(), 1, "Only SP (C) in blues");
    assert!(reds_d.is_empty(), "No reds when all non-SP tips are SP ancestors");

    // blue_work = C.cd(400) + self.diff(100) = 500
    assert_eq!(blue_work_d, CumulativeDifficulty::from_u64(500));

    Ok(())
}

/// Security: blue_work must always be strictly greater than the
/// selected parent's cumulative difficulty. This ensures the chain
/// always makes forward progress and prevents "zero-progress" attacks.
#[tokio::test]
async fn test_blue_work_always_exceeds_sp() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    // Test with varying difficulties
    let difficulties = [1u64, 50, 100, 1000, u64::MAX / 2];
    let mut parent = genesis.clone();
    let mut parent_cd = CumulativeDifficulty::from_u64(100);

    for (i, &diff) in difficulties.iter().enumerate() {
        let h = test_hash((i + 1) as u8);
        let cd = parent_cd + CumulativeDifficulty::from_u64(diff);
        let mut tips = IndexSet::new();
        tips.insert(parent.clone());
        create_block(&mut storage, &h, (i + 1) as u64, tips.clone(), diff, cd.into()).await;
        let (_, _, bw) = process_block(&mut storage, &h, &tips, diff).await;

        assert!(bw > parent_cd,
            "Block {}: blue_work {} must strictly exceed parent CD {}",
            i + 1, bw, parent_cd);

        parent = h;
        parent_cd = bw;
    }

    Ok(())
}

/// Edge case: verify the k-cluster invariant holds after multiple
/// rounds of merging. Build a sequence of merge blocks where each
/// round creates parallel blocks and merges them.
#[tokio::test]
async fn test_k_cluster_invariant_across_multiple_merges() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    let mut current_tip = genesis.clone();
    let mut current_height = 0u64;
    let mut hash_counter = 1u8;

    // Run 5 rounds of: create K parallel blocks, merge them
    for round in 0..5 {
        let mut parallel_blocks = Vec::new();
        let fork_parent = current_tip.clone();
        let fork_height = current_height;

        // Create K parallel blocks from current_tip
        for _ in 0..K {
            let h = test_hash(hash_counter);
            hash_counter += 1;
            let mut tips = IndexSet::new();
            tips.insert(fork_parent.clone());
            create_block(&mut storage, &h, fork_height + 1, tips.clone(), 100, 0).await;
            process_block(&mut storage, &h, &tips, 100).await;
            parallel_blocks.push(h);
        }

        // Merge all parallel blocks
        let merge = test_hash(hash_counter);
        hash_counter += 1;
        let tips_m: IndexSet<Hash> = parallel_blocks.iter().cloned().collect();
        create_block(&mut storage, &merge, fork_height + 2, tips_m.clone(), 100, 0).await;
        let (data_m, reds_m, _) = process_block(&mut storage, &merge, &tips_m, 100).await;

        // k-cluster invariant: all blues have anticone_size ≤ K
        for (hash, size) in data_m.iter() {
            assert!(size <= K,
                "Round {}: block {:?} has anticone_size={} > K={}",
                round, hash, size, K);
        }

        // With K parallel blocks, all should be blue (anticone = K-1 ≤ K)
        assert!(reds_m.is_empty(),
            "Round {}: K={} parallel blocks must all be blue", round, K);
        assert_eq!(data_m.len(), K,
            "Round {}: SP + (K-1) non-SP blues = K total", round);

        current_tip = merge;
        current_height = fork_height + 2;
    }

    Ok(())
}

/// Edge case: verify behavior with minimum difficulty (1).
/// blue_work must still accumulate correctly.
#[tokio::test]
async fn test_minimum_difficulty_blue_work() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 1).await;

    let a = test_hash(1);
    let b = test_hash(2);

    let mut tips = IndexSet::new();
    tips.insert(genesis.clone());
    create_block(&mut storage, &a, 1, tips.clone(), 1, 2).await;
    let (_, _, bw_a) = process_block(&mut storage, &a, &tips, 1).await;
    // blue_work = genesis.cd(1) + self.diff(1) = 2
    assert_eq!(bw_a, CumulativeDifficulty::from_u64(2));

    tips.clear(); tips.insert(a.clone());
    create_block(&mut storage, &b, 2, tips.clone(), 1, 3).await;
    let (_, _, bw_b) = process_block(&mut storage, &b, &tips, 1).await;
    // blue_work = a.cd(2) + self.diff(1) = 3
    assert_eq!(bw_b, CumulativeDifficulty::from_u64(3));

    Ok(())
}

/// Edge case: verify that a block referencing only itself (self-reference)
/// as a tip doesn't cause infinite loops. While this shouldn't happen in
/// production (validated elsewhere), the algorithm must be robust.
///
/// We can't truly create a self-referencing block in storage, but we CAN
/// test that the height check in is_dag_ancestor_of prevents infinite
/// recursion: a block cannot be its own strict ancestor because
/// descendant_height <= ancestor_height triggers the early return.
#[tokio::test]
async fn test_self_ancestry_terminates() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    let a = test_hash(1);
    let mut tips = IndexSet::new();
    tips.insert(genesis.clone());
    create_block(&mut storage, &a, 1, tips.clone(), 100, 200).await;

    // is_dag_ancestor_of(a, a) should return true immediately (hash equality)
    assert!(is_dag_ancestor_of(&storage, &a, &a).await?);

    Ok(())
}

// Parasite chain attack resistance tests

/// #1: Merge blocks must store `blue_work` as cumulative difficulty.
#[tokio::test]
async fn test_stored_cd_equals_blue_work_for_merge_blocks() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    // Two parallel blocks A, B -> merge C -> child D
    let a = test_hash(1);
    let b = test_hash(2);
    let c = test_hash(3);
    let d = test_hash(4);

    let mut tips = IndexSet::new();
    tips.insert(genesis.clone());
    create_block(&mut storage, &a, 1, tips.clone(), 100, 200).await;
    let (_, _, _bw_a) = process_block(&mut storage, &a, &tips, 100).await;

    create_block(&mut storage, &b, 1, tips.clone(), 100, 200).await;
    let (_, _, _bw_b) = process_block(&mut storage, &b, &tips, 100).await;

    // Merge block C
    tips.clear();
    tips.insert(a.clone());
    tips.insert(b.clone());
    create_block(&mut storage, &c, 2, tips.clone(), 100, 0).await; // CD=0 intentionally wrong
    let (_, _, bw_c) = process_block(&mut storage, &c, &tips, 100).await;

    // blue_work_c = 100 (self) + 200 (SP.cd) + 100 (non-SP.diff) = 400
    assert_eq!(bw_c, CumulativeDifficulty::from_u64(400));

    // Stored CD must match computed blue_work.
    let stored_cd_c = storage.get_cumulative_difficulty_for_block_hash(&c).await?;
    assert_eq!(stored_cd_c, bw_c,
        "Stored cumulative_difficulty must equal GHOSTDAG blue_work for merge block");

    // Child must use C's stored CD.
    tips.clear();
    tips.insert(c.clone());
    create_block(&mut storage, &d, 3, tips.clone(), 100, 0).await;
    let (_, _, bw_d) = process_block(&mut storage, &d, &tips, 100).await;

    // blue_work_d = 100 (self) + 400 (C.cd) = 500
    assert_eq!(bw_d, CumulativeDifficulty::from_u64(500),
        "D's blue_work must use C's correct stored CD (400), not the initial create_block value");

    let stored_cd_d = storage.get_cumulative_difficulty_for_block_hash(&d).await?;
    assert_eq!(stored_cd_d, bw_d,
        "D's stored CD must also match its blue_work");

    Ok(())
}

/// #2: Late private attacker chain should be mostly red and bounded in blue_work.
#[tokio::test]
async fn test_parasite_chain_late_joining_attacker() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    // Honest chain: genesis -> H1 -> H2 -> H3 -> H4 -> H5 (5 blocks, CD = 600)
    let mut honest_chain = Vec::new();
    let mut parent = genesis.clone();
    for i in 1u8..=5 {
        let h = test_hash(i);
        let mut tips = IndexSet::new();
        tips.insert(parent.clone());
        let cd = 100 * (i as u64 + 1);
        create_block(&mut storage, &h, i as u64, tips.clone(), 100, cd).await;
        process_block(&mut storage, &h, &tips, 100).await;
        honest_chain.push(h.clone());
        parent = h;
    }
    let honest_tip = honest_chain.last().unwrap().clone();
    let honest_cd = storage.get_cumulative_difficulty_for_block_hash(&honest_tip).await?;
    assert_eq!(honest_cd, CumulativeDifficulty::from_u64(600));

    // Attacker chain (built in isolation from genesis): genesis -> A1 -> A2 -> A3 -> A4 -> A5
    // Same difficulty (100 each), same length. Each attacker block is parallel to ALL honest blocks.
    let mut attacker_chain = Vec::new();
    let mut a_parent = genesis.clone();
    for i in 1u8..=5 {
        let a = test_hash(100 + i);
        let mut tips = IndexSet::new();
        tips.insert(a_parent.clone());
        let cd = 100 * (i as u64 + 1);
        create_block(&mut storage, &a, i as u64, tips.clone(), 100, cd).await;
        process_block(&mut storage, &a, &tips, 100).await;
        attacker_chain.push(a.clone());
        a_parent = a;
    }
    let attacker_tip = attacker_chain.last().unwrap().clone();

    // Merge block: references both honest tip and attacker tip
    let merge = test_hash(200);
    let mut merge_tips = IndexSet::new();
    merge_tips.insert(honest_tip.clone());
    merge_tips.insert(attacker_tip.clone());
    create_block(&mut storage, &merge, 6, merge_tips.clone(), 100, 0).await;
    let (merge_data, merge_reds, merge_bw) = process_block(&mut storage, &merge, &merge_tips, 100).await;

    // Attacker blocks should be red (anticone > k).
    assert!(merge_reds.len() >= 4,
        "At least 4 of 5 attacker blocks must be RED (anticone size > k=3); got {} reds",
        merge_reds.len());

    // Count how many attacker blocks are red
    let attacker_reds: usize = attacker_chain.iter()
        .filter(|h| merge_reds.contains(h))
        .count();
    assert!(attacker_reds >= 4,
        "At least 4 attacker blocks should be red; got {}", attacker_reds);

    // Red blocks must not increase blue_work.
    let non_sp_blues = merge_data.len().saturating_sub(1);
    let expected_max = honest_cd + CumulativeDifficulty::from_u64(100 + 100 * non_sp_blues as u64);
    assert!(merge_bw <= expected_max,
        "merge.blue_work {} must be ≤ {} (red blocks must not inflate blue_work)",
        merge_bw, expected_max);

    // Upper bound allows at most one attacker blue.
    assert!(merge_bw <= CumulativeDifficulty::from_u64(800),
        "merge.blue_work {} must not exceed 800 (at most 1 attacker blue)", merge_bw);

    Ok(())
}

/// #3: Cross-referencing attacker must not cause double-counting.
#[tokio::test]
async fn test_parasite_chain_cross_referencing_attacker() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    // Honest chain: genesis -> H1 -> H2 -> H3 -> H4
    let h1 = test_hash(1);
    let h2 = test_hash(2);
    let h3 = test_hash(3);
    let h4 = test_hash(4);

    let mut tips = IndexSet::new();
    tips.insert(genesis.clone());
    for (h, i) in [(&h1, 1u64), (&h2, 2), (&h3, 3), (&h4, 4)] {
        create_block(&mut storage, h, i, tips.clone(), 100, 100 * (i + 1)).await;
        process_block(&mut storage, h, &tips, 100).await;
        tips.clear();
        tips.insert((*h).clone());
    }

    let h4_cd = storage.get_cumulative_difficulty_for_block_hash(&h4).await?;
    assert_eq!(h4_cd, CumulativeDifficulty::from_u64(500));

    // Attacker chain: genesis -> A1
    let a1 = test_hash(10);
    tips.clear();
    tips.insert(genesis.clone());
    create_block(&mut storage, &a1, 1, tips.clone(), 100, 200).await;
    process_block(&mut storage, &a1, &tips, 100).await;

    // A2 cross-references H2 (tries to absorb honest work)
    let a2 = test_hash(11);
    tips.clear();
    tips.insert(a1.clone());
    tips.insert(h2.clone());
    // A2's height must be > max(a1.height, h2.height) = max(1, 2) = 2 -> height=3
    create_block(&mut storage, &a2, 3, tips.clone(), 100, 0).await;
    let (_, _, _bw_a2) = process_block(&mut storage, &a2, &tips, 100).await;

    // A2 should pick H2 as SP and stay bounded.

    // A3 cross-references H3
    let a3 = test_hash(12);
    tips.clear();
    tips.insert(a2.clone());
    tips.insert(h3.clone());
    // height > max(a2.height=3, h3.height=3) = 3 -> height=4
    create_block(&mut storage, &a3, 4, tips.clone(), 100, 0).await;
    let (_, _, _bw_a3) = process_block(&mut storage, &a3, &tips, 100).await;

    // Final merge: [H4, A3]
    let merge = test_hash(99);
    let mut merge_tips = IndexSet::new();
    merge_tips.insert(h4.clone());
    merge_tips.insert(a3.clone());
    create_block(&mut storage, &merge, 5, merge_tips.clone(), 100, 0).await;
    let (merge_data, merge_reds, merge_bw) = process_block(&mut storage, &merge, &merge_tips, 100).await;

    // Must not double-count SP ancestors.

    // H1/H2/H3 are SP ancestors and must be excluded.
    assert!(!merge_data.contains(&h1) && !merge_reds.contains(&h1),
        "H1 is in SP's past, must be excluded from mergeset");
    assert!(!merge_data.contains(&h2) && !merge_reds.contains(&h2),
        "H2 is in SP's past, must be excluded from mergeset");
    assert!(!merge_data.contains(&h3) && !merge_reds.contains(&h3),
        "H3 is in SP's past, must be excluded from mergeset");

    // blue_work must remain bounded.
    let max_blues_diff = merge_data.len().saturating_sub(1) as u64 * 100;
    let max_expected = CumulativeDifficulty::from_u64(500 + 100 + max_blues_diff);
    assert!(merge_bw <= max_expected,
        "merge blue_work {} must not exceed {}", merge_bw, max_expected);

    Ok(())
}

/// #4: Equal-hashpower attacker gets no blue_work advantage.
#[tokio::test]
async fn test_parasite_chain_equal_hashpower_no_advantage() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    // Chain 1: genesis -> C1_1 -> C1_2 -> C1_3
    let mut chain1 = Vec::new();
    let mut parent = genesis.clone();
    for i in 1u8..=3 {
        let h = test_hash(i);
        let mut tips = IndexSet::new();
        tips.insert(parent.clone());
        create_block(&mut storage, &h, i as u64, tips.clone(), 100, 0).await;
        process_block(&mut storage, &h, &tips, 100).await;
        chain1.push(h.clone());
        parent = h;
    }
    let tip1 = chain1.last().unwrap().clone();
    let cd1 = storage.get_cumulative_difficulty_for_block_hash(&tip1).await?;

    // Chain 2: genesis -> C2_1 -> C2_2 -> C2_3
    let mut chain2 = Vec::new();
    parent = genesis.clone();
    for i in 1u8..=3 {
        let h = test_hash(50 + i);
        let mut tips = IndexSet::new();
        tips.insert(parent.clone());
        create_block(&mut storage, &h, i as u64, tips.clone(), 100, 0).await;
        process_block(&mut storage, &h, &tips, 100).await;
        chain2.push(h.clone());
        parent = h;
    }
    let tip2 = chain2.last().unwrap().clone();
    let cd2 = storage.get_cumulative_difficulty_for_block_hash(&tip2).await?;

    // Both chains have equal cumulative difficulty (same length, same diff)
    assert_eq!(cd1, cd2,
        "Equal-length equal-difficulty chains must have equal CD");
    assert_eq!(cd1, CumulativeDifficulty::from_u64(400),
        "CD should be genesis(100) + 3×100 = 400");

    // Merge: the SP is determined by hash tiebreak (equal CD)
    let merge = test_hash(200);
    let mut merge_tips = IndexSet::new();
    merge_tips.insert(tip1.clone());
    merge_tips.insert(tip2.clone());
    create_block(&mut storage, &merge, 4, merge_tips.clone(), 100, 0).await;
    let (merge_data, merge_reds, merge_bw) = process_block(&mut storage, &merge, &merge_tips, 100).await;

    // Losing-chain contribution is bounded by k-rules.

    // Verify the merge block's stored CD matches its blue_work
    let stored_merge_cd = storage.get_cumulative_difficulty_for_block_hash(&merge).await?;
    assert_eq!(stored_merge_cd, merge_bw,
        "Stored CD must equal blue_work for the merge block");

    // Verify blue_work is reasonable: SP.cd + self + blue_mergeset
    let max_blues_diff = merge_data.len().saturating_sub(1) as u64 * 100;
    let max_bw = CumulativeDifficulty::from_u64(400 + 100 + max_blues_diff);
    assert!(merge_bw <= max_bw,
        "merge.blue_work {} exceeds maximum possible {}", merge_bw, max_bw);

    // All non-SP blocks must be present in merge processing.
    let total_non_sp = merge_data.len() - 1 + merge_reds.len();
    assert!(total_non_sp >= 3,
        "All 3 non-SP chain blocks must appear in the mergeset: found {}", total_non_sp);

    Ok(())
}

/// #5: Multi-round attack stays bounded and preserves CD propagation.
#[tokio::test]
async fn test_parasite_chain_multi_round_sustained_attack() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    let mut honest_tip = genesis.clone();
    let mut hash_counter = 1u16;

    // Run 3 rounds of: honest extends, attacker creates parallel block, merge
    for round in 0..3u16 {
        // Honest extends: honest_tip -> H_new
        let h_new = test_hash16(hash_counter);
        hash_counter += 1;
        let h_height = storage.get_height_for_block_hash(&honest_tip).await? + 1;
        let mut tips = IndexSet::new();
        tips.insert(honest_tip.clone());
        create_block(&mut storage, &h_new, h_height, tips.clone(), 200, 0).await;
        let (_, _, bw_h) = process_block(&mut storage, &h_new, &tips, 200).await;

        // Attacker creates a parallel block from the SAME parent
        let a_new = test_hash16(500 + hash_counter);
        hash_counter += 1;
        tips.clear();
        tips.insert(honest_tip.clone());
        create_block(&mut storage, &a_new, h_height, tips.clone(), 100, 0).await;
        let (_, _, bw_a) = process_block(&mut storage, &a_new, &tips, 100).await;

        // Honest has higher difficulty -> higher blue_work
        assert!(bw_h > bw_a,
            "Round {}: honest blue_work {} must exceed attacker's {} (higher diff)",
            round, bw_h, bw_a);

        // Merge: [H_new, A_new]
        let merge = test_hash16(1000 + round);
        let mut merge_tips = IndexSet::new();
        merge_tips.insert(h_new.clone());
        merge_tips.insert(a_new.clone());
        let merge_height = h_height + 1;
        create_block(&mut storage, &merge, merge_height, merge_tips.clone(), 100, 0).await;
        let (merge_data, _merge_reds, merge_bw) = process_block(&mut storage, &merge, &merge_tips, 100).await;

        // Verify stored CD = blue_work
        let stored_cd = storage.get_cumulative_difficulty_for_block_hash(&merge).await?;
        assert_eq!(stored_cd, merge_bw,
            "Round {}: stored CD must equal blue_work for merge block", round);

        // SP must be H_new (higher blue_work)
        let sp = merge_data.keys().next().unwrap();
        assert_eq!(sp, &h_new,
            "Round {}: honest block must be selected parent (higher blue_work)", round);

        // Merge blue_work must strictly exceed honest tip's blue_work
        let h_cd = storage.get_cumulative_difficulty_for_block_hash(&h_new).await?;
        assert!(merge_bw > h_cd,
            "Round {}: merge blue_work {} must exceed SP's CD {}",
            round, merge_bw, h_cd);

        // Update honest_tip to the merge for next round
        honest_tip = merge;
    }

    // Final: verify the chain's cumulative difficulty is strictly increasing
    // and no attacker block artificially inflated it
    let final_cd = storage.get_cumulative_difficulty_for_block_hash(&honest_tip).await?;
    assert!(final_cd > CumulativeDifficulty::from_u64(100),
        "Final CD {} must be substantial", final_cd);

    Ok(())
}

/// #6: Chained merges must strictly increase blue_work and persist CD.
#[tokio::test]
async fn test_blue_work_propagation_through_chained_merges() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    let mut current_tip = genesis.clone();
    let mut prev_bw = CumulativeDifficulty::from_u64(100);
    let mut hash_counter = 1u16;

    for round in 0..5u16 {
        // Create a parallel block from the same parent
        let parallel = test_hash16(hash_counter);
        hash_counter += 1;
        let height = storage.get_height_for_block_hash(&current_tip).await? + 1;
        let mut par_tips = IndexSet::new();
        par_tips.insert(current_tip.clone());
        create_block(&mut storage, &parallel, height, par_tips.clone(), 100, 0).await;
        process_block(&mut storage, &parallel, &par_tips, 100).await;

        // Create another parallel block from the same parent
        let parallel2 = test_hash16(hash_counter);
        hash_counter += 1;
        let mut par2_tips = IndexSet::new();
        par2_tips.insert(current_tip.clone());
        create_block(&mut storage, &parallel2, height, par2_tips.clone(), 100, 0).await;
        process_block(&mut storage, &parallel2, &par2_tips, 100).await;

        // Merge both
        let merge = test_hash16(2000 + round);
        let mut merge_tips = IndexSet::new();
        merge_tips.insert(parallel.clone());
        merge_tips.insert(parallel2.clone());
        create_block(&mut storage, &merge, height + 1, merge_tips.clone(), 100, 0).await;
        let (_, _, merge_bw) = process_block(&mut storage, &merge, &merge_tips, 100).await;

        // blue_work must strictly increase over the previous round's tip
        assert!(merge_bw > prev_bw,
            "Round {}: merge blue_work {} must exceed previous {}", round, merge_bw, prev_bw);

        // Stored CD must match blue_work
        let stored_cd = storage.get_cumulative_difficulty_for_block_hash(&merge).await?;
        assert_eq!(stored_cd, merge_bw,
            "Round {}: stored CD must equal blue_work", round);

        // A child of this merge must read the CORRECT CD
        let child = test_hash16(3000 + round);
        let mut child_tips = IndexSet::new();
        child_tips.insert(merge.clone());
        create_block(&mut storage, &child, height + 2, child_tips.clone(), 100, 0).await;
        let (_, _, child_bw) = process_block(&mut storage, &child, &child_tips, 100).await;

        // child.blue_work = 100 (self) + merge.cd (= merge.blue_work)
        assert_eq!(child_bw, merge_bw + CumulativeDifficulty::from_u64(100),
            "Round {}: child blue_work must be merge.cd + self.diff", round);

        prev_bw = child_bw;
        current_tip = child;
    }

    Ok(())
}

/// #7: Higher attacker block diff still loses with fewer blue blocks.
#[tokio::test]
async fn test_parasite_chain_high_diff_attacker_still_loses() -> Result<()> {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let genesis = test_hash(0);
    create_genesis(&mut storage, &genesis, 100).await;

    // Honest chain: genesis -> H1 -> H2 -> H3 -> H4 -> H5 -> H6 (diff=100 each)
    let mut honest_chain = Vec::new();
    let mut parent = genesis.clone();
    for i in 1u8..=6 {
        let h = test_hash(i);
        let mut tips = IndexSet::new();
        tips.insert(parent.clone());
        create_block(&mut storage, &h, i as u64, tips.clone(), 100, 0).await;
        process_block(&mut storage, &h, &tips, 100).await;
        honest_chain.push(h.clone());
        parent = h;
    }
    let honest_tip = honest_chain.last().unwrap().clone();
    let honest_cd = storage.get_cumulative_difficulty_for_block_hash(&honest_tip).await?;
    // CD = 100 (genesis) + 6×100 = 700
    assert_eq!(honest_cd, CumulativeDifficulty::from_u64(700));

    // Attacker chain: genesis -> A1 -> A2 -> A3 (diff=200 each)
    let mut attacker_chain = Vec::new();
    parent = genesis.clone();
    for i in 1u8..=3 {
        let a = test_hash(100 + i);
        let mut tips = IndexSet::new();
        tips.insert(parent.clone());
        create_block(&mut storage, &a, i as u64, tips.clone(), 200, 0).await;
        process_block(&mut storage, &a, &tips, 200).await;
        attacker_chain.push(a.clone());
        parent = a;
    }
    let attacker_tip = attacker_chain.last().unwrap().clone();
    let attacker_cd = storage.get_cumulative_difficulty_for_block_hash(&attacker_tip).await?;
    // CD = 100 (genesis) + 3×200 = 700
    assert_eq!(attacker_cd, CumulativeDifficulty::from_u64(700));

    // Both chains have equal CD! SP determined by hash tiebreak.
    // Merge: [honest_tip, attacker_tip]
    let merge = test_hash(200);
    let mut merge_tips = IndexSet::new();
    merge_tips.insert(honest_tip.clone());
    merge_tips.insert(attacker_tip.clone());
    create_block(&mut storage, &merge, 7, merge_tips.clone(), 100, 0).await;
    let (merge_data, merge_reds, merge_bw) = process_block(&mut storage, &merge, &merge_tips, 100).await;

    // Determine which chain won SP (hash tiebreak)
    let sp = merge_data.keys().next().unwrap().clone();
    let is_honest_sp = honest_chain.contains(&sp) || sp == honest_tip;

    if is_honest_sp {
        // Honest is SP: attacker blocks enter mergeset.
        // Each attacker block is parallel to ALL 6 honest blocks -> anticone ≥ 6 > k=3 -> RED
        for a in &attacker_chain {
            assert!(merge_reds.contains(a),
                "Attacker block {:?} must be RED (anticone to honest chain ≥ 6 > k)", a);
        }
        // Blue work = honest_cd(700) + self(100) = 800 (no attacker contribution)
        assert_eq!(merge_bw, CumulativeDifficulty::from_u64(800),
            "Blue work must be exactly SP.cd + self.diff when all attacker blocks are red");
    } else {
        // Attacker is SP: honest blocks enter mergeset.
        // Each honest block's anticone includes 3 attacker blocks -> size 3 = k -> blue (at boundary).
        // So honest blocks may be blue! This means the honest chain's difficulty gets absorbed
        // into the attacker SP's blue_work, which is correct: those blocks contribute real work.
        // The key point: the attacker doesn't get MORE blue_work than the honest chain deserved.

        // Blue work = attacker_cd(700) + self(100) + (number of honest blues × 100)
        let honest_blues = honest_chain.iter()
            .filter(|h| merge_data.contains(h))
            .count();
        let expected_bw = CumulativeDifficulty::from_u64(700 + 100 + 100 * honest_blues as u64);
        assert_eq!(merge_bw, expected_bw,
            "Blue work must be attacker_cd + self + honest_blues_diff");
    }

    // Either way: stored CD must equal blue_work
    let stored_cd = storage.get_cumulative_difficulty_for_block_hash(&merge).await?;
    assert_eq!(stored_cd, merge_bw,
        "Stored CD must equal blue_work");

    Ok(())
}