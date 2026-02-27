use anyhow::Result;
use crate::core::storage::MemoryStorage;
use xelis_common::network::Network;
use super::common::*;

#[tokio::test]
async fn test_memory_transactions() -> Result<()> {
    let data = TestData::new()?;
    let storage = MemoryStorage::new(Network::Devnet, 1);
    test_transaction_operations(storage, &data).await
}

#[tokio::test]
async fn test_memory_nonces() -> Result<()> {
    let data = TestData::new()?;
    let storage = MemoryStorage::new(Network::Devnet, 1);
    test_nonce_operations(storage, &data).await
}

#[tokio::test]
async fn test_memory_blocks() -> Result<()> {
    let data = TestData::new()?;
    let storage = MemoryStorage::new(Network::Devnet, 1);
    test_block_operations(storage, &data).await
}

#[tokio::test]
async fn test_memory_multiple_hashes() -> Result<()> {
    let data = TestData::new()?;
    let storage = MemoryStorage::new(Network::Devnet, 1);
    test_multiple_hashes(storage, &data).await
}

#[tokio::test]
async fn test_memory_nonce_increment() -> Result<()> {
    let data = TestData::new()?;
    let storage = MemoryStorage::new(Network::Devnet, 1);
    test_nonce_increment(storage, &data).await
}

#[tokio::test]
async fn test_memory_overwrite_nonce() -> Result<()> {
    let data = TestData::new()?;
    let storage = MemoryStorage::new(Network::Devnet, 1);
    test_overwrite_nonce(storage, &data).await
}

#[tokio::test]
async fn test_memory_multiple_blocks() -> Result<()> {
    let data = TestData::new()?;
    let storage = MemoryStorage::new(Network::Devnet, 1);
    test_multiple_blocks(storage, &data).await
}

#[tokio::test]
async fn test_memory_contract_event_callback_storage() -> Result<()> {
    let storage = MemoryStorage::new(Network::Devnet, 1);
    test_contract_event_callback_storage(storage).await
}

#[tokio::test]
async fn test_memory_contract_event_callback_retrieval() -> Result<()> {
    let storage = MemoryStorage::new(Network::Devnet, 1);
    test_contract_event_callback_retrieval(storage).await
}

#[tokio::test]
async fn test_memory_contract_event_callback_versioning() -> Result<()> {
    let storage = MemoryStorage::new(Network::Devnet, 1);
    test_contract_event_callback_versioning(storage).await
}

#[tokio::test]
async fn test_memory_event_callback_unregister() -> Result<()> {
    let storage = MemoryStorage::new(Network::Devnet, 1);
    test_event_callback_unregister(storage).await
}

#[tokio::test]
async fn test_memory_contract_scheduled_execution_storage() -> Result<()> {
    let storage = MemoryStorage::new(Network::Devnet, 1);
    test_contract_scheduled_execution_storage(storage).await
}

#[tokio::test]
async fn test_memory_contract_scheduled_execution_retrieval() -> Result<()> {
    let data = TestData::new()?;
    let storage = MemoryStorage::new(Network::Devnet, 1);
    test_contract_scheduled_execution_retrieval(storage, &data).await
}

#[tokio::test]
async fn test_memory_contract_scheduled_execution_at_topoheight_range() -> Result<()> {
    let storage = MemoryStorage::new(Network::Devnet, 1);
    test_contract_scheduled_execution_at_topoheight_range(storage).await
}

#[tokio::test]
async fn test_memory_cleanup_above_topoheight_with_mixed_data() -> Result<()> {
    let data = TestData::new()?;
    let storage = MemoryStorage::new(Network::Devnet, 1);
    test_cleanup_above_topoheight_with_mixed_data(storage, &data).await
}

#[tokio::test]
async fn test_memory_cleanup_below_topoheight_with_mixed_data() -> Result<()> {
    let data = TestData::new()?;
    let storage = MemoryStorage::new(Network::Devnet, 1);
    test_cleanup_below_topoheight_with_mixed_data(storage, &data).await
}

#[tokio::test]
async fn test_memory_cleanup_all_data_types_at_topoheight() -> Result<()> {
    let data = TestData::new()?;
    let storage = MemoryStorage::new(Network::Devnet, 1);
    test_cleanup_all_data_types_at_topoheight(storage, &data).await
}

#[tokio::test]
async fn test_memory_versioned_nonce_at_max_topoheight() -> Result<()> {
    let data = TestData::new()?;
    let storage = MemoryStorage::new(Network::Devnet, 1);
    test_versioned_nonce_at_max_topoheight(storage, &data).await
}

#[tokio::test]
async fn test_memory_versioned_contract_event_callback_stream() -> Result<()> {
    let storage = MemoryStorage::new(Network::Devnet, 1);
    test_versioned_contract_event_callback_stream(storage).await
}

#[tokio::test]
async fn test_memory_versioned_scheduled_execution_in_range() -> Result<()> {
    let storage = MemoryStorage::new(Network::Devnet, 1);
    test_versioned_scheduled_execution_in_range(storage).await
}

#[tokio::test]
async fn test_memory_versioned_data_max_topoheight_boundary() -> Result<()> {
    let data = TestData::new()?;
    let storage = MemoryStorage::new(Network::Devnet, 1);
    test_versioned_data_max_topoheight_boundary(storage, &data).await
}

#[tokio::test]
async fn test_memory_delete_versioned_data_at_topoheight_nonces() -> Result<()> {
    let data = TestData::new()?;
    let storage = MemoryStorage::new(data.network, 1);
    test_delete_versioned_data_at_topoheight_nonces(storage, &data).await
}

#[tokio::test]
async fn test_memory_delete_versioned_data_below_topoheight_nonces() -> Result<()> {
    let data = TestData::new()?;
    let storage = MemoryStorage::new(data.network, 1);
    test_delete_versioned_data_below_topoheight_nonces(storage, &data).await
}

#[tokio::test]
async fn test_memory_delete_versioned_data_above_topoheight_nonces() -> Result<()> {
    let data = TestData::new()?;
    let storage = MemoryStorage::new(data.network, 1);
    test_delete_versioned_data_above_topoheight_nonces(storage, &data).await
}

#[tokio::test]
async fn test_memory_delete_versioned_data_at_topoheight_contracts() -> Result<()> {
    let storage = MemoryStorage::new(Network::Devnet, 1);
    test_delete_versioned_data_at_topoheight_contracts(storage).await
}

#[tokio::test]
async fn test_memory_delete_versioned_data_below_topoheight_contracts() -> Result<()> {
    let storage = MemoryStorage::new(Network::Devnet, 1);
    test_delete_versioned_data_below_topoheight_contracts(storage).await
}

#[tokio::test]
async fn test_memory_delete_versioned_data_above_topoheight_contracts() -> Result<()> {
    let storage = MemoryStorage::new(Network::Devnet, 1);
    test_delete_versioned_data_above_topoheight_contracts(storage).await
}

#[tokio::test]
async fn test_memory_delete_versioned_data_at_topoheight_mixed() -> Result<()> {
    let data = TestData::new()?;
    let storage = MemoryStorage::new(data.network, 1);
    test_delete_versioned_data_at_topoheight_mixed(storage, &data).await
}

#[tokio::test]
async fn test_memory_delete_versioned_data_below_topoheight_mixed() -> Result<()> {
    let data = TestData::new()?;
    let storage = MemoryStorage::new(data.network, 1);
    test_delete_versioned_data_below_topoheight_mixed(storage, &data).await
}

#[tokio::test]
async fn test_memory_delete_versioned_data_above_topoheight_mixed() -> Result<()> {
    let data = TestData::new()?;
    let storage = MemoryStorage::new(data.network, 1);
    test_delete_versioned_data_above_topoheight_mixed(storage, &data).await
}
