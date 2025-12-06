use super::*;
use crate::entry::{EntryData, TransactionEntry};
use xelis_common::{
    crypto::Hash,
    network::Network,
};
use std::{
    sync::atomic::{AtomicU64, Ordering},
    fs
};

// Helper to create a test storage with unique database
fn create_test_storage() -> Result<EncryptedStorage> {
    
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let mut temp_path = std::env::temp_dir();
    temp_path.push(format!("xelis_wallet_test_{}", id));
    
    // Clean up if it exists
    let _ = fs::remove_dir_all(&temp_path);
    
    let storage = Storage::new(temp_path.to_str().unwrap())?;
    // Key must be exactly 32 bytes for XChaCha20Poly1305
    let key: [u8; 32] = [42u8; 32];
    let salt = [0u8; SALT_SIZE];
    let encrypted = EncryptedStorage::new(storage, &key, salt, Network::Testnet)?;
    Ok(encrypted)
}

// Helper to create a test transaction entry
fn create_test_tx(hash: &Hash, topoheight: u64) -> TransactionEntry {
    TransactionEntry::new(
        hash.clone(),
        topoheight,
        0, // timestamp
        EntryData::Coinbase { reward: 1000 },
    )
}

#[test]
fn test_transaction_insertion_order() {
    let mut storage = create_test_storage().unwrap();

    // Insert transactions in random order
    let txs = vec![
        (Hash::new([1u8; 32]), 100),
        (Hash::new([2u8; 32]), 50),
        (Hash::new([3u8; 32]), 150),
        (Hash::new([4u8; 32]), 75),
        (Hash::new([5u8; 32]), 125),
    ];

    for (hash, topo) in &txs {
        let entry = create_test_tx(&hash, *topo);
        storage.save_transaction(hash, &entry).unwrap();
    }

    // Verify indexes are sequential
    for i in 0..txs.len() {
        let result = storage.transactions_indexes.get(&(i as u64).to_be_bytes()).unwrap();
        assert!(result.is_some(), "Index {} should exist", i);
    }

    // Verify we can retrieve all transactions
    let count = storage.get_transactions_count().unwrap();
    assert_eq!(count, txs.len(), "Should have all transactions");
}

#[test]
fn test_binary_search_exact_match() {
    let mut storage = create_test_storage().unwrap();

    // Insert transactions with different topoheights
    let topoheights = vec![10, 20, 30, 40, 50];
    for (i, topo) in topoheights.iter().enumerate() {
        let hash = Hash::new([i as u8; 32]);
        let entry = create_test_tx(&hash, *topo);
        storage.save_transaction(&hash, &entry).unwrap();
    }

    // Test exact matches with lowest=true
    for (i, topo) in topoheights.iter().enumerate() {
        let result = storage.search_transaction_id_for_topoheight(*topo, None, None, true).unwrap();
        assert_eq!(result, Some(i as u64), "Should find exact match for topoheight {}", topo);
    }

    // Test exact matches with lowest=false
    for (i, topo) in topoheights.iter().enumerate() {
        let result = storage.search_transaction_id_for_topoheight(*topo, None, None, false).unwrap();
        assert_eq!(result, Some(i as u64), "Should find exact match for topoheight {} (highest)", topo);
    }
}

#[test]
fn test_binary_search_multiple_same_topoheight() {
    let mut storage = create_test_storage().unwrap();

    // Insert multiple transactions with the same topoheight
    let topoheights = vec![10, 20, 20, 20, 30, 40, 40, 50];
    for (i, topo) in topoheights.iter().enumerate() {
        let hash = Hash::new([i as u8; 32]);
        let entry = create_test_tx(&hash, *topo);
        storage.save_transaction(&hash, &entry).unwrap();
    }

    // Test finding lowest index for topoheight 20 (should be index 1)
    let result = storage.search_transaction_id_for_topoheight(20, None, None, true).unwrap();
    assert_eq!(result, Some(1), "Should find lowest index for topoheight 20");

    // Test finding highest index for topoheight 20 (should be index 3)
    let result = storage.search_transaction_id_for_topoheight(20, None, None, false).unwrap();
    assert_eq!(result, Some(3), "Should find highest index for topoheight 20");

    // Test finding lowest index for topoheight 40 (should be index 5)
    let result = storage.search_transaction_id_for_topoheight(40, None, None, true).unwrap();
    assert_eq!(result, Some(5), "Should find lowest index for topoheight 40");

    // Test finding highest index for topoheight 40 (should be index 6)
    let result = storage.search_transaction_id_for_topoheight(40, None, None, false).unwrap();
    assert_eq!(result, Some(6), "Should find highest index for topoheight 40");
}

#[test]
fn test_binary_search_no_exact_match() {
    let mut storage = create_test_storage().unwrap();

    // Insert transactions with gaps in topoheights
    let topoheights = vec![10, 20, 40, 50, 60];
    for (i, topo) in topoheights.iter().enumerate() {
        let hash = Hash::new([i as u8; 32]);
        let entry = create_test_tx(&hash, *topo);
        storage.save_transaction(&hash, &entry).unwrap();
    }

    // Search for topoheight 25 (between 20 and 40)
    // Should return index 2 (first tx with topoheight >= 25, which is 40)
    let result = storage.search_transaction_id_for_topoheight(25, None, None, true).unwrap();
    assert_eq!(result, Some(2), "Should find next higher topoheight for 25");

    // Search for topoheight 35 (between 20 and 40)
    // Should return index 2 (first tx with topoheight >= 35, which is 40)
    let result = storage.search_transaction_id_for_topoheight(35, None, None, true).unwrap();
    assert_eq!(result, Some(2), "Should find next higher topoheight for 35");

    // Search for topoheight 5 (before first)
    // Should return index 0 (first tx with topoheight >= 5, which is 10)
    let result = storage.search_transaction_id_for_topoheight(5, None, None, true).unwrap();
    assert_eq!(result, Some(0), "Should find first tx for topoheight 5");

    // Search for topoheight 100 (after last)
    // Should return None (no tx with topoheight >= 100)
    let result = storage.search_transaction_id_for_topoheight(100, None, None, true).unwrap();
    assert_eq!(result, None, "Should return None for topoheight beyond all transactions");
}

#[test]
fn test_binary_search_with_bounds() {
    let mut storage = create_test_storage().unwrap();

    // Insert transactions
    let topoheights = vec![10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
    for (i, topo) in topoheights.iter().enumerate() {
        let hash = Hash::new([i as u8; 32]);
        let entry = create_test_tx(&hash, *topo);
        storage.save_transaction(&hash, &entry).unwrap();
    }

    // Search with left bound
    let result = storage.search_transaction_id_for_topoheight(50, Some(3), None, true).unwrap();
    assert_eq!(result, Some(4), "Should find topoheight 50 starting from index 3");

    // Search with right bound
    let result = storage.search_transaction_id_for_topoheight(50, None, Some(7), true).unwrap();
    assert_eq!(result, Some(4), "Should find topoheight 50 ending at index 7");

    // Search with both bounds
    let result = storage.search_transaction_id_for_topoheight(60, Some(3), Some(7), true).unwrap();
    assert_eq!(result, Some(5), "Should find topoheight 60 within bounds");
}

#[test]
fn test_delete_transactions_above_topoheight() {
    let mut storage = create_test_storage().unwrap();

    // Insert transactions
    let topoheights = vec![10, 20, 30, 40, 50, 60, 70];
    let hashes: Vec<Hash> = (0..topoheights.len())
        .map(|i| Hash::new([i as u8; 32]))
        .collect();

    for (i, topo) in topoheights.iter().enumerate() {
        let entry = create_test_tx(&hashes[i], *topo);
        storage.save_transaction(&hashes[i], &entry).unwrap();
    }

    // Delete transactions above topoheight 40
    storage.delete_transactions_above_topoheight(40).unwrap();

    // Verify transactions with topoheight > 40 are deleted
    for (i, topo) in topoheights.iter().enumerate() {
        let exists = storage.has_transaction(&hashes[i]).unwrap();
        if *topo > 40 {
            assert!(!exists, "Transaction at topoheight {} should be deleted", topo);
        } else {
            assert!(exists, "Transaction at topoheight {} should still exist", topo);
        }
    }

    // Verify count
    let count = storage.get_transactions_count().unwrap();
    assert_eq!(count, 4, "Should have 4 transactions remaining");
}

#[test]
fn test_delete_transactions_at_or_above_topoheight() {
    let mut storage = create_test_storage().unwrap();

    // Insert transactions
    let topoheights = vec![10, 20, 30, 40, 50, 60, 70];
    let hashes: Vec<Hash> = (0..topoheights.len())
        .map(|i| Hash::new([i as u8; 32]))
        .collect();

    for (i, topo) in topoheights.iter().enumerate() {
        let entry = create_test_tx(&hashes[i], *topo);
        storage.save_transaction(&hashes[i], &entry).unwrap();
    }

    // Delete transactions at or above topoheight 40
    storage.delete_transactions_at_or_above_topoheight(40).unwrap();

    // Verify transactions with topoheight >= 40 are deleted
    for (i, topo) in topoheights.iter().enumerate() {
        let exists = storage.has_transaction(&hashes[i]).unwrap();
        if *topo >= 40 {
            assert!(!exists, "Transaction at topoheight {} should be deleted", topo);
        } else {
            assert!(exists, "Transaction at topoheight {} should still exist", topo);
        }
    }

    // Verify count
    let count = storage.get_transactions_count().unwrap();
    assert_eq!(count, 3, "Should have 3 transactions remaining");
}

#[test]
fn test_reorder_transactions_indexes() {
    let mut storage = create_test_storage().unwrap();

    // Insert transactions in order
    let initial_order = vec![
        (Hash::new([1u8; 32]), 10),
        (Hash::new([2u8; 32]), 20),
        (Hash::new([3u8; 32]), 30),
        (Hash::new([4u8; 32]), 40),
        (Hash::new([5u8; 32]), 50),
    ];

    for (hash, topo) in &initial_order {
        let entry = create_test_tx(hash, *topo);
        storage.save_transaction(hash, &entry).unwrap();
    }

    // Simulate a reorg: update transactions 3, 4, 5 with new topoheights
    // New order should be: 10, 20, 45, 35, 55 -> sorted: 10, 20, 35, 45, 55
    let new_topoheights = vec![
        (Hash::new([3u8; 32]), 45),
        (Hash::new([4u8; 32]), 35),
        (Hash::new([5u8; 32]), 55),
    ];

    for (hash, new_topo) in &new_topoheights {
        let entry = create_test_tx(hash, *new_topo);
        storage.update_transaction(hash, &entry).unwrap();
    }

    // Reorder indexes from position 2 onwards
    storage.reorder_transactions_indexes(Some(1)).unwrap();

    // Verify the new order in indexes
    // Index 0: hash1 (topo 10)
    // Index 1: hash2 (topo 20)
    // Index 2: hash4 (topo 35)
    // Index 3: hash3 (topo 45)
    // Index 4: hash5 (topo 55)
    let expected_order = vec![
        (Hash::new([1u8; 32]), 10),
        (Hash::new([2u8; 32]), 20),
        (Hash::new([4u8; 32]), 35),
        (Hash::new([3u8; 32]), 45),
        (Hash::new([5u8; 32]), 55),
    ];

    for (i, (expected_hash, expected_topo)) in expected_order.iter().enumerate() {
        let tx_hash = storage.transactions_indexes.get(&(i as u64).to_be_bytes()).unwrap().unwrap();
        let entry: TransactionEntry = storage.load_from_disk_with_key(&storage.transactions, &tx_hash).unwrap();
        
        assert_eq!(entry.get_hash(), expected_hash, "Hash mismatch at index {}", i);
        assert_eq!(entry.get_topoheight(), *expected_topo, "Topoheight mismatch at index {}", i);
    }
}

#[test]
fn test_reorder_all_transactions() {
    let mut storage = create_test_storage().unwrap();

    // Insert transactions in random order
    let txs = vec![
        (Hash::new([1u8; 32]), 50),
        (Hash::new([2u8; 32]), 20),
        (Hash::new([3u8; 32]), 80),
        (Hash::new([4u8; 32]), 10),
        (Hash::new([5u8; 32]), 60),
    ];

    for (hash, topo) in &txs {
        let entry = create_test_tx(hash, *topo);
        storage.save_transaction(hash, &entry).unwrap();
    }

    // Reorder all transactions from the beginning
    storage.reorder_transactions_indexes(None).unwrap();

    // Expected order after sorting by topoheight: 10, 20, 50, 60, 80
    let expected_order = vec![
        (Hash::new([4u8; 32]), 10),
        (Hash::new([2u8; 32]), 20),
        (Hash::new([1u8; 32]), 50),
        (Hash::new([5u8; 32]), 60),
        (Hash::new([3u8; 32]), 80),
    ];

    for (i, (expected_hash, expected_topo)) in expected_order.iter().enumerate() {
        let tx_hash = storage.transactions_indexes.get(&(i as u64).to_be_bytes()).unwrap().unwrap();
        let entry: TransactionEntry = storage.load_from_disk_with_key(&storage.transactions, &tx_hash).unwrap();
        
        assert_eq!(entry.get_hash(), expected_hash, "Hash mismatch at index {} after full reorder", i);
        assert_eq!(entry.get_topoheight(), *expected_topo, "Topoheight mismatch at index {} after full reorder", i);
    }
}

#[test]
fn test_get_filtered_transactions_by_topoheight_range() {
    let mut storage = create_test_storage().unwrap();

    // Insert transactions with various topoheights
    let topoheights = vec![10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
    for (i, topo) in topoheights.iter().enumerate() {
        let hash = Hash::new([i as u8; 32]);
        let entry = create_test_tx(&hash, *topo);
        storage.save_transaction(&hash, &entry).unwrap();
    }

    // Test range with both min and max (inclusive)
    let result = storage.get_filtered_transactions(
        None, None, Some(30), Some(70), true, true, true, true, None, None, None
    ).unwrap();
    assert_eq!(result.len(), 5, "Should return 5 transactions (30, 40, 50, 60, 70)");
    
    // Verify topoheights are correct
    let topos: Vec<u64> = result.iter().map(|t| t.get_topoheight()).collect();
    assert_eq!(topos, vec![70, 60, 50, 40, 30], "Should return in reverse order");

    // Test range with only min
    let result = storage.get_filtered_transactions(
        None, None, Some(80), None, true, true, true, true, None, None, None
    ).unwrap();
    assert_eq!(result.len(), 3, "Should return 3 transactions (80, 90, 100)");

    // Test range with only max
    let result = storage.get_filtered_transactions(
        None, None, None, Some(30), true, true, true, true, None, None, None
    ).unwrap();
    assert_eq!(result.len(), 3, "Should return 3 transactions (10, 20, 30)");
}

#[test]
fn test_get_filtered_transactions_with_limit() {
    let mut storage = create_test_storage().unwrap();

    // Insert transactions
    for i in 0..10 {
        let hash = Hash::new([i; 32]);
        let entry = create_test_tx(&hash, i as u64 * 10);
        storage.save_transaction(&hash, &entry).unwrap();
    }

    // Test with limit
    let result = storage.get_filtered_transactions(
        None, None, None, None, true, true, true, true, None, Some(5), None
    ).unwrap();
    assert_eq!(result.len(), 5, "Should return only 5 transactions");
}

#[test]
fn test_get_filtered_transactions_with_skip() {
    let mut storage = create_test_storage().unwrap();

    // Insert transactions
    for i in 0..10 {
        let hash = Hash::new([i; 32]);
        let entry = create_test_tx(&hash, i as u64 * 10);
        storage.save_transaction(&hash, &entry).unwrap();
    }

    // Test with skip
    let result = storage.get_filtered_transactions(
        None, None, None, None, true, true, true, true, None, None, Some(3)
    ).unwrap();
    assert_eq!(result.len(), 7, "Should skip first 3 and return 7 transactions");
    
    // First transaction should have topoheight 60 (skipping 90, 80, 70)
    assert_eq!(result[0].get_topoheight(), 60, "First result should be at topoheight 60");
}

#[test]
fn test_rebuild_transactions_indexes() {
    let mut storage = create_test_storage().unwrap();

    // Insert transactions
    let topoheights = vec![50, 20, 80, 10, 60];
    let hashes: Vec<Hash> = (0..topoheights.len())
        .map(|i| Hash::new([i as u8; 32]))
        .collect();

    for (i, topo) in topoheights.iter().enumerate() {
        let entry = create_test_tx(&hashes[i], *topo);
        storage.save_transaction(&hashes[i], &entry).unwrap();
    }

    // Corrupt the indexes by clearing them
    storage.transactions_indexes.clear().unwrap();

    // Rebuild
    storage.rebuild_transactions_indexes().unwrap();

    // Verify indexes are correct and sorted by topoheight
    let expected_order = vec![
        (Hash::new([3u8; 32]), 10),
        (Hash::new([1u8; 32]), 20),
        (Hash::new([0u8; 32]), 50),
        (Hash::new([4u8; 32]), 60),
        (Hash::new([2u8; 32]), 80),
    ];

    for (i, (expected_hash, expected_topo)) in expected_order.iter().enumerate() {
        let tx_hash = storage.transactions_indexes.get(&(i as u64).to_be_bytes()).unwrap().unwrap();
        let entry: TransactionEntry = storage.load_from_disk_with_key(&storage.transactions, &tx_hash).unwrap();
        
        assert_eq!(entry.get_hash(), expected_hash, "Hash mismatch at index {} after rebuild", i);
        assert_eq!(entry.get_topoheight(), *expected_topo, "Topoheight mismatch at index {} after rebuild", i);
    }
}

#[test]
fn test_edge_case_empty_storage() {
    let storage = create_test_storage().unwrap();

    // Test binary search on empty storage
    let result = storage.search_transaction_id_for_topoheight(50, None, None, true).unwrap();
    assert_eq!(result, None, "Should return None for empty storage");

    // Test filtered transactions on empty storage
    let result = storage.get_filtered_transactions(
        None, None, None, None, true, true, true, true, None, None, None
    ).unwrap();
    assert_eq!(result.len(), 0, "Should return empty vec for empty storage");

    // Test count
    let count = storage.get_transactions_count().unwrap();
    assert_eq!(count, 0, "Should have 0 transactions");
}

#[test]
fn test_edge_case_single_transaction() {
    let mut storage = create_test_storage().unwrap();

    let hash = Hash::new([1u8; 32]);
    let entry = create_test_tx(&hash, 50);
    storage.save_transaction(&hash, &entry).unwrap();

    // Test exact match
    let result = storage.search_transaction_id_for_topoheight(50, None, None, true).unwrap();
    assert_eq!(result, Some(0), "Should find the single transaction");

    // Test below
    let result = storage.search_transaction_id_for_topoheight(40, None, None, true).unwrap();
    assert_eq!(result, Some(0), "Should find the single transaction for lower topoheight");

    // Test above
    let result = storage.search_transaction_id_for_topoheight(60, None, None, true).unwrap();
    assert_eq!(result, None, "Should return None for topoheight above the single transaction");
}

#[test]
fn test_key_usage_consistency() {
    let mut storage = create_test_storage().unwrap();

    let hash = Hash::new([1u8; 32]);
    let entry = create_test_tx(&hash, 50);
    
    // Save transaction
    storage.save_transaction(&hash, &entry).unwrap();

    // Verify the key in transactions_indexes is a plain u64
    let index_key = storage.transactions_indexes.last().unwrap().unwrap();
    assert_eq!(index_key.0.len(), 8, "Index key should be 8 bytes (u64)");

    // Verify the value in transactions_indexes is a hashed key
    let hashed_key = index_key.1;
    let expected_hashed_key = storage.cipher.hash_key(hash.as_bytes());
    assert_eq!(hashed_key.len(), expected_hashed_key.len(), "Hashed key length should match");

    // Verify we can retrieve the transaction using the hashed key
    let retrieved = storage.transactions.get(&hashed_key).unwrap();
    assert!(retrieved.is_some(), "Should be able to retrieve transaction with hashed key");
}
