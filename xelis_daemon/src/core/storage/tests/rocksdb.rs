use anyhow::{Context, Result};
use tempdir::TempDir;
use crate::core::storage::RocksStorage;
use crate::core::config::RocksDBConfig;
use xelis_common::{crypto::PublicKey, network::Network};
use super::{
    common::*,
    super::*,
};

fn new_rocksdb_storage(network: Network, path: &str) -> Result<RocksStorage> {
    // Create a default RocksDB config
    let config = RocksDBConfig::default();
    Ok(RocksStorage::new(path, network, &config, 1)?)
}

#[tokio::test]
async fn test_rocksdb_transactions() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_transaction_operations(storage, &data).await
}

#[tokio::test]
async fn test_rocksdb_nonces() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_nonce_operations(storage, &data).await
}

#[tokio::test]
async fn test_rocksdb_blocks() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_block_operations(storage, &data).await
}

#[tokio::test]
async fn test_rocksdb_multiple_hashes() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_multiple_hashes(storage, &data).await
}

#[tokio::test]
async fn test_rocksdb_nonce_increment() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_nonce_increment(storage, &data).await
}

#[tokio::test]
async fn test_rocksdb_overwrite_nonce() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_overwrite_nonce(storage, &data).await
}

#[tokio::test]
async fn test_rocksdb_multiple_blocks() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_multiple_blocks(storage, &data).await
}

// Event callback tests
#[tokio::test]
async fn test_rocksdb_contract_event_callback_storage() -> Result<()> {
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_contract_event_callback_storage(storage).await
}

#[tokio::test]
async fn test_rocksdb_contract_event_callback_retrieval() -> Result<()> {
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_contract_event_callback_retrieval(storage).await
}

#[tokio::test]
async fn test_rocksdb_contract_event_callback_versioning() -> Result<()> {
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_contract_event_callback_versioning(storage).await
}

#[tokio::test]
async fn test_rocksdb_event_callback_unregister() -> Result<()> {
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_event_callback_unregister(storage).await
}

// Scheduled execution tests
#[tokio::test]
async fn test_rocksdb_contract_scheduled_execution_storage() -> Result<()> {
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_contract_scheduled_execution_storage(storage).await
}

#[tokio::test]
async fn test_rocksdb_contract_scheduled_execution_retrieval() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_contract_scheduled_execution_retrieval(storage, &data).await
}

#[tokio::test]
async fn test_rocksdb_contract_scheduled_execution_at_topoheight_range() -> Result<()> {
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_contract_scheduled_execution_at_topoheight_range(storage).await
}

// Cleanup tests
#[tokio::test]
async fn test_rocksdb_cleanup_above_topoheight_with_mixed_data() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_cleanup_above_topoheight_with_mixed_data(storage, &data).await
}

#[tokio::test]
async fn test_rocksdb_cleanup_below_topoheight_with_mixed_data() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_cleanup_below_topoheight_with_mixed_data(storage, &data).await
}

#[tokio::test]
async fn test_rocksdb_cleanup_all_data_types_at_topoheight() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_cleanup_all_data_types_at_topoheight(storage, &data).await
}

// Versioned data tests
#[tokio::test]
async fn test_rocksdb_versioned_nonce_at_max_topoheight() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_versioned_nonce_at_max_topoheight(storage, &data).await
}

#[tokio::test]
async fn test_rocksdb_versioned_contract_event_callback_stream() -> Result<()> {
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_versioned_contract_event_callback_stream(storage).await
}

#[tokio::test]
async fn test_rocksdb_event_callbacks_available_at_maximum_topoheight() -> Result<()> {
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_event_callbacks_available_at_maximum_topoheight(storage).await
}

#[tokio::test]
async fn test_rocksdb_event_callbacks_available_after_rewind() -> Result<()> {
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_event_callbacks_available_after_rewind(storage).await
}

#[tokio::test]
async fn test_rocksdb_listeners_for_contract_events() -> Result<()> {
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_listeners_for_contract_events(storage).await
}

#[tokio::test]
async fn test_rocksdb_versioned_scheduled_execution_in_range() -> Result<()> {
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_versioned_scheduled_execution_in_range(storage).await
}

#[tokio::test]
async fn test_rocksdb_versioned_data_max_topoheight_boundary() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_versioned_data_max_topoheight_boundary(storage, &data).await
}

#[tokio::test]
async fn test_rocksdb_delete_versioned_data_at_topoheight_nonces() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_delete_versioned_data_at_topoheight_nonces(storage, &data).await
}

#[tokio::test]
async fn test_rocksdb_delete_versioned_data_below_topoheight_nonces() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_delete_versioned_data_below_topoheight_nonces(storage, &data).await
}

#[tokio::test]
async fn test_rocksdb_delete_versioned_data_above_topoheight_nonces() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_delete_versioned_data_above_topoheight_nonces(storage, &data).await
}

#[tokio::test]
async fn test_rocksdb_delete_versioned_data_at_topoheight_contracts() -> Result<()> {
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_delete_versioned_data_at_topoheight_contracts(storage).await
}

#[tokio::test]
async fn test_rocksdb_delete_versioned_data_below_topoheight_contracts() -> Result<()> {
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_delete_versioned_data_below_topoheight_contracts(storage).await
}

#[tokio::test]
async fn test_rocksdb_delete_versioned_data_above_topoheight_contracts() -> Result<()> {
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_delete_versioned_data_above_topoheight_contracts(storage).await
}

#[tokio::test]
async fn test_rocksdb_delete_versioned_data_at_topoheight_mixed() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_delete_versioned_data_at_topoheight_mixed(storage, &data).await
}

#[tokio::test]
async fn test_rocksdb_delete_versioned_data_below_topoheight_mixed() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_delete_versioned_data_below_topoheight_mixed(storage, &data).await
}

#[tokio::test]
async fn test_rocksdb_delete_versioned_data_above_topoheight_mixed() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_delete_versioned_data_above_topoheight_mixed(storage, &data).await
}

#[tokio::test]
async fn test_rocksdb_delete_versioned_balances_above_topoheight() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_delete_versioned_balances_above_topoheight(storage, &data).await
}

#[tokio::test]
async fn test_rocksdb_delete_versioned_balances_above_topoheight_multi_account() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_delete_versioned_balances_above_topoheight_multi_account(storage).await
}

#[tokio::test]
async fn test_rocksdb_delete_versioned_balances_pop_blocks_scenario() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_delete_versioned_balances_pop_blocks_scenario(storage, &data).await
}

// This test exercises the same pop_blocks scenario through the high-level
// storage API: multiple accounts each with many versioned balances across many
// topoheights.  It verifies that after delete_versioned_data_above_topoheight
// every account pointer lands at exactly the cutoff, not above it.
#[tokio::test]
async fn test_rocksdb_balance_rewind_multi_account_and_topoheight() -> Result<()> {
    use xelis_common::{
        account::VersionedBalance,
        asset::{AssetData, AssetOwner, MaxSupplyMode, VersionedAssetData},
        crypto::{Hash, KeyPair},
    };

    let data = TestData::new()?;
    let temp_dir = TempDir::new("storage_test")?;
    let mut storage = new_rocksdb_storage(data.network, temp_dir.path().to_str().unwrap())?;

    let asset = Hash::new([0u8; 32]);

    storage.add_asset(
        &asset,
        0,
        VersionedAssetData::new(
            AssetData::new(8, "Test".to_owned(), "TST".to_owned(), MaxSupplyMode::Fixed(u64::MAX), AssetOwner::None),
            None,
        ),
    ).await.context("add_asset")?;

    // Create several accounts and write balances at many topoheights so that
    // the VersionedBalances column has entries spread across many prefix groups.
    let keys: Vec<PublicKey> = (0..8).map(|_| KeyPair::new().get_public_key().compress()).collect();
    let cutoff = 15u64;
    let max_topo = 30u64;

    for key in &keys {
        storage.set_account_registration_topoheight(key, 0).await?;

        let mut bal = VersionedBalance::zero();
        storage.set_last_balance_to(key, &asset, 0, &bal).await?;
        for topo in 1u64..=max_topo {
            bal.set_previous_topoheight(Some(topo - 1));
            storage.set_last_balance_to(key, &asset, topo, &bal).await?;
        }
    }

    // Flush data to disk so the iterator runs against SST files, not the memtable.
    // (The memtable does not use bloom filters, so the bug would not manifest
    // without this step.)
    storage.flush_and_compact().await.context("flush_and_compact")?;

    storage.delete_versioned_data_above_topoheight(cutoff).await
        .context("delete_versioned_data_above_topoheight")?;

    // Every account's balance pointer must be exactly at the cutoff.
    for (idx, key) in keys.iter().enumerate() {
        let (topo, _) = storage.get_last_balance(key, &asset).await
            .with_context(|| format!("get_last_balance account {}", idx))?;
        assert_eq!(topo, cutoff,
            "account {} pointer is {} after rewind, expected {}", idx, topo, cutoff);
    }

    // Entries above the cutoff must be gone for the first account.
    for topo in (cutoff + 1)..=max_topo {
        let exists = storage.has_balance_at_exact_topoheight(&keys[0], &asset, topo).await?;
        assert!(!exists, "balance at topo {} should be gone after delete_above({})", topo, cutoff);
    }

    Ok(())
}
#[tokio::test]
async fn test_rocksdb_event_callback_consumed_versioning() -> Result<()> {
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_event_callback_consumed_versioning(storage).await
}

#[tokio::test]
async fn test_rocksdb_contract_data_lifecycle() -> Result<()> {
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_contract_data_lifecycle(storage).await
}

#[tokio::test]
async fn test_rocksdb_contract_data_rewind() -> Result<()> {
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_contract_data_rewind(storage).await
}

#[tokio::test]
async fn test_rocksdb_contract_module_lifecycle() -> Result<()> {
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_contract_module_lifecycle(storage).await
}

#[tokio::test]
async fn test_rocksdb_contract_module_rewind() -> Result<()> {
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_contract_module_rewind(storage).await
}

#[tokio::test]
async fn test_rocksdb_scheduled_execution_lifecycle() -> Result<()> {
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_scheduled_execution_lifecycle(storage).await
}

#[tokio::test]
async fn test_rocksdb_scheduled_execution_range_query() -> Result<()> {
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_scheduled_execution_range_query(storage).await
}

#[tokio::test]
async fn test_rocksdb_account_registration_topoheight() -> Result<()> {
    let temp_dir = TempDir::new("storage_test")?;
    let storage = new_rocksdb_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_account_registration_topoheight(storage).await
}