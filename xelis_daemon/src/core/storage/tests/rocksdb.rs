use anyhow::Result;
use tempdir::TempDir;
use crate::core::storage::RocksStorage;
use crate::core::config::RocksDBConfig;
use xelis_common::network::Network;
use super::common::*;

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