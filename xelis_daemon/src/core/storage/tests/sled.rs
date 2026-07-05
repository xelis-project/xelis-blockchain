use anyhow::Result;
use tempfile::TempDir;
use xelis_common::network::Network;
use super::{
    common::*,
    super::*,
};

fn new_sled_storage(network: Network, path: &str) -> Result<SledStorage> {
    let config = SledConfig::default();
    Ok(SledStorage::new(
        path.to_string(),
        if config.cache_size > 0 { Some(config.cache_size) } else { None },
        network,
        config.internal_cache_size,
        config.internal_db_mode,
        1
    )?)
}

#[tokio::test]
async fn test_sled_transactions() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_transaction_operations(storage, &data).await
}

#[tokio::test]
async fn test_sled_nonces() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_nonce_operations(storage, &data).await
}

#[tokio::test]
async fn test_sled_blocks() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_block_operations(storage, &data).await
}

#[tokio::test]
async fn test_sled_multiple_hashes() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_multiple_hashes(storage, &data).await
}

#[tokio::test]
async fn test_sled_nonce_increment() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_nonce_increment(storage, &data).await
}

#[tokio::test]
async fn test_sled_overwrite_nonce() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_overwrite_nonce(storage, &data).await
}

#[tokio::test]
async fn test_sled_multiple_blocks() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_multiple_blocks(storage, &data).await
}

// Event callback tests
#[tokio::test]
async fn test_sled_contract_event_callback_storage() -> Result<()> {
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_contract_event_callback_storage(storage).await
}

#[tokio::test]
async fn test_sled_contract_event_callback_retrieval() -> Result<()> {
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_contract_event_callback_retrieval(storage).await
}

#[tokio::test]
async fn test_sled_contract_event_callback_versioning() -> Result<()> {
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_contract_event_callback_versioning(storage).await
}

#[tokio::test]
async fn test_sled_event_callback_unregister() -> Result<()> {
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_event_callback_unregister(storage).await
}

// Scheduled execution tests
#[tokio::test]
async fn test_sled_contract_scheduled_execution_storage() -> Result<()> {
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_contract_scheduled_execution_storage(storage).await
}

#[tokio::test]
async fn test_sled_contract_scheduled_execution_retrieval() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_contract_scheduled_execution_retrieval(storage, &data).await
}

#[tokio::test]
async fn test_sled_contract_scheduled_execution_at_topoheight_range() -> Result<()> {
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_contract_scheduled_execution_at_topoheight_range(storage).await
}

// Cleanup tests
#[tokio::test]
async fn test_sled_cleanup_above_topoheight_with_mixed_data() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_cleanup_above_topoheight_with_mixed_data(storage, &data).await
}

#[tokio::test]
async fn test_sled_cleanup_below_topoheight_with_mixed_data() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_cleanup_below_topoheight_with_mixed_data(storage, &data).await
}

#[tokio::test]
async fn test_sled_cleanup_all_data_types_at_topoheight() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_cleanup_all_data_types_at_topoheight(storage, &data).await
}

// Versioned data tests
#[tokio::test]
async fn test_sled_versioned_nonce_at_max_topoheight() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_versioned_nonce_at_max_topoheight(storage, &data).await
}

#[tokio::test]
async fn test_sled_versioned_contract_event_callback_stream() -> Result<()> {
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_versioned_contract_event_callback_stream(storage).await
}

#[tokio::test]
async fn test_sled_event_callbacks_available_at_maximum_topoheight() -> Result<()> {
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_event_callbacks_available_at_maximum_topoheight(storage).await
}

#[tokio::test]
async fn test_sled_event_callbacks_available_after_rewind() -> Result<()> {
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_event_callbacks_available_after_rewind(storage).await
}

#[tokio::test]
async fn test_sled_listeners_for_contract_events() -> Result<()> {
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_listeners_for_contract_events(storage).await
}

#[tokio::test]
async fn test_sled_versioned_scheduled_execution_in_range() -> Result<()> {
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_versioned_scheduled_execution_in_range(storage).await
}

#[tokio::test]
async fn test_sled_versioned_data_max_topoheight_boundary() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_versioned_data_max_topoheight_boundary(storage, &data).await
}

#[tokio::test]
async fn test_sled_asset_data_at_maximum_topoheight_walks_previous_versions() -> Result<()> {
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_asset_data_at_maximum_topoheight(storage).await
}

#[tokio::test]
async fn test_sled_asset_supply_at_maximum_topoheight_walks_previous_versions() -> Result<()> {
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_asset_supply_at_maximum_topoheight(storage).await
}

#[tokio::test]
async fn test_sled_delete_versioned_data_at_topoheight_nonces() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_delete_versioned_data_at_topoheight_nonces(storage, &data).await
}

#[tokio::test]
async fn test_sled_delete_versioned_data_below_topoheight_nonces() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_delete_versioned_data_below_topoheight_nonces(storage, &data).await
}

#[tokio::test]
async fn test_sled_delete_versioned_data_above_topoheight_nonces() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_delete_versioned_data_above_topoheight_nonces(storage, &data).await
}

#[tokio::test]
async fn test_sled_delete_versioned_data_at_topoheight_contracts() -> Result<()> {
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_delete_versioned_data_at_topoheight_contracts(storage).await
}

#[tokio::test]
async fn test_sled_delete_versioned_data_below_topoheight_contracts() -> Result<()> {
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_delete_versioned_data_below_topoheight_contracts(storage).await
}

#[tokio::test]
async fn test_sled_delete_versioned_data_above_topoheight_contracts() -> Result<()> {
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_delete_versioned_data_above_topoheight_contracts(storage).await
}

#[tokio::test]
async fn test_sled_delete_versioned_data_at_topoheight_mixed() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_delete_versioned_data_at_topoheight_mixed(storage, &data).await
}

#[tokio::test]
async fn test_sled_delete_versioned_data_below_topoheight_mixed() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_delete_versioned_data_below_topoheight_mixed(storage, &data).await
}

#[tokio::test]
async fn test_sled_delete_versioned_data_above_topoheight_mixed() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_delete_versioned_data_above_topoheight_mixed(storage, &data).await
}

#[tokio::test]
async fn test_sled_delete_versioned_balances_above_topoheight() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_delete_versioned_balances_above_topoheight(storage, &data).await
}

#[tokio::test]
async fn test_sled_delete_versioned_balances_below_topoheight_keeps_latest_output() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_delete_versioned_balances_below_topoheight_keeps_latest_output(storage, &data).await
}

#[tokio::test]
async fn test_sled_delete_versioned_balances_above_topoheight_multi_account() -> Result<()> {
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_delete_versioned_balances_above_topoheight_multi_account(storage).await
}

#[tokio::test]
async fn test_sled_delete_versioned_balances_pop_blocks_scenario() -> Result<()> {
    let data = TestData::new()?;
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(data.network, temp_dir.path().to_str().unwrap())?;
    test_delete_versioned_balances_pop_blocks_scenario(storage, &data).await
}

#[tokio::test]
async fn test_sled_event_callback_consumed_versioning() -> Result<()> {
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_event_callback_consumed_versioning(storage).await
}

#[tokio::test]
async fn test_sled_contract_data_lifecycle() -> Result<()> {
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_contract_data_lifecycle(storage).await
}

#[tokio::test]
async fn test_sled_contract_data_rewind() -> Result<()> {
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_contract_data_rewind(storage).await
}

#[tokio::test]
async fn test_sled_contract_module_lifecycle() -> Result<()> {
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_contract_module_lifecycle(storage).await
}

#[tokio::test]
async fn test_sled_contract_module_rewind() -> Result<()> {
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_contract_module_rewind(storage).await
}

#[tokio::test]
async fn test_sled_scheduled_execution_lifecycle() -> Result<()> {
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_scheduled_execution_lifecycle(storage).await
}

#[tokio::test]
async fn test_sled_scheduled_execution_prune_keeps_future_execution() -> Result<()> {
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_scheduled_execution_prune_keeps_future_execution(storage).await
}

#[tokio::test]
async fn test_sled_scheduled_execution_range_query() -> Result<()> {
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_scheduled_execution_range_query(storage).await
}

#[tokio::test]
async fn test_sled_account_registration_topoheight() -> Result<()> {
    let temp_dir = TempDir::with_prefix("storage_test")?;
    let storage = new_sled_storage(Network::Devnet, temp_dir.path().to_str().unwrap())?;
    test_account_registration_topoheight(storage).await
}
