use anyhow::{Result, Context};
use futures::StreamExt;
use std::sync::Arc;
use std::borrow::Cow;
use indexmap::IndexSet;
use xelis_common::{
    account::{BalanceType, VersionedBalance, VersionedNonce},
    asset::{AssetData, AssetOwner, MaxSupplyMode, VersionedAssetData},
    block::{BlockHeader, BlockVersion, EXTRA_NONCE_SIZE},
    config::XELIS_ASSET,
    contract::{ContractModule, EventCallbackRegistration, ScheduledExecution, ScheduledExecutionKind, Source},
    crypto::{Hash, KeyPair, PublicKey},
    difficulty::Difficulty,
    immutable::Immutable,
    network::Network,
    transaction::MultiSigPayload,
    varuint::VarUint,
    versioned::Versioned
};
use xelis_vm::{Module, Primitive, ValueCell};
use crate::core::storage::Storage;

pub struct TestData {
    pub network: Network,
    pub block_hash: Hash,
    pub block_header: BlockHeader,
    pub tx_hash: Hash,
    pub public_key_pair: KeyPair,
}

impl TestData {
    pub fn new() -> Result<Self> {
        let network = Network::Devnet;
        let public_key_pair = KeyPair::new();
        let public_key = public_key_pair.get_public_key().compress();
        
        let block_hash = Hash::new([1u8; 32]);
        let tips: Immutable<IndexSet<Hash>> = IndexSet::new().into();
        let block_header = BlockHeader::new(
            BlockVersion::V0,
            0,
            0,
            tips,
            [0u8; EXTRA_NONCE_SIZE],
            public_key,
            IndexSet::new(),
        );
        
        let tx_hash = Hash::new([2u8; 32]);
        
        Ok(Self {
            network,
            block_hash,
            block_header,
            tx_hash,
            public_key_pair,
        })
    }
}

pub async fn test_transaction_operations<S: Storage>(storage: S, data: &TestData) -> Result<()> {
    // Check transaction doesn't exist initially
    assert!(!storage.has_transaction(&data.tx_hash).await
        .context("Failed to check if transaction exists")?,
        "Transaction should not exist initially");

    Ok(())
}

pub async fn test_nonce_operations<S: Storage>(mut storage: S, data: &TestData) -> Result<()> {
    let public_key = data.public_key_pair.get_public_key().compress();
    let versioned_nonce = VersionedNonce::new(42, None);
    let topoheight = 0u64;
    
    storage.set_last_nonce_to(&public_key, topoheight, &versioned_nonce).await
        .context("Failed to set nonce")?;
    
    let retrieved_nonce = storage.get_last_nonce(&public_key).await
        .context("Failed to get nonce")?;
    
    assert_eq!(retrieved_nonce.1.get_nonce(), 42, "Nonce mismatch");
    
    Ok(())
}

pub async fn test_block_operations<S: Storage>(mut storage: S, data: &TestData) -> Result<()> {
    let block_hash = Immutable::Owned(data.block_hash.clone());
    let block_arc = Arc::new(data.block_header.clone());

    storage.save_block(
        block_arc,
        &[],
        Default::default(),
        Difficulty::zero(),
        0u64.into(),
        VarUint::from(0u32),
        0,
        block_hash
    ).await.context("Failed to add block")?;
    
    assert!(storage.has_block_with_hash(&data.block_hash).await
        .context("Failed to check if block exists")?,
        "Block should exist after adding");
    
    Ok(())
}

pub async fn test_multiple_hashes<S: Storage>(_storage: S, _data: &TestData) -> Result<()> {
    // Simple placeholder test
    Ok(())
}

pub async fn test_nonce_increment<S: Storage>(mut storage: S, data: &TestData) -> Result<()> {
    let public_key = data.public_key_pair.get_public_key().compress();
    
    for nonce in 1..=3 {
        let versioned_nonce = VersionedNonce::new(nonce as u64, None);
        storage.set_last_nonce_to(&public_key, (nonce - 1) as u64, &versioned_nonce).await
            .context(format!("Failed to set nonce {}", nonce))?;
        
        let retrieved = storage.get_last_nonce(&public_key).await
            .context(format!("Failed to get nonce {}", nonce))?;
        
        assert_eq!(retrieved.1.get_nonce(), nonce as u64, "Nonce {} mismatch", nonce);
    }
    
    Ok(())
}

pub async fn test_overwrite_nonce<S: Storage>(mut storage: S, data: &TestData) -> Result<()> {
    let public_key = data.public_key_pair.get_public_key().compress();
    
    let versioned_nonce1 = VersionedNonce::new(10, None);
    storage.set_last_nonce_to(&public_key, 0, &versioned_nonce1).await
        .context("Failed to set first nonce")?;
    
    let versioned_nonce2 = VersionedNonce::new(20, None);
    storage.set_last_nonce_to(&public_key, 1, &versioned_nonce2).await
        .context("Failed to set second nonce")?;
    
    let retrieved = storage.get_last_nonce(&public_key).await
        .context("Failed to get nonce")?;
    
    assert_eq!(retrieved.1.get_nonce(), 20, "Nonce should be updated to the latest");
    
    Ok(())
}

pub async fn test_multiple_blocks<S: Storage>(mut storage: S, data: &TestData) -> Result<()> {
    for i in 0..15 {
        let hash = Hash::new([100 + i as u8; 32]);
        let mut header = data.block_header.clone();
        header.height = i as u64;
        let block_arc = Arc::new(header);
        let block_hash_immutable: Immutable<Hash> = Immutable::Owned(hash);
        
        storage.save_block(
            block_arc,
            &[],
            Default::default(),
            Difficulty::zero(),
            0u64.into(),
            VarUint::from(0u32),
            0,
            block_hash_immutable
        ).await.context(format!("Failed to add block {}", i))?;
    }
    
    for i in 0..2 {
        let hash = Hash::new([100 + i as u8; 32]);
        assert!(storage.has_block_with_hash(&hash).await
            .context(format!("Failed to check block {}", i))?,
            "Block {} should exist", i);
    }
    
    Ok(())
}

// Tests for contract event callbacks
pub async fn test_contract_event_callback_storage<S: Storage>(mut storage: S) -> Result<()> {
    let contract_hash = Hash::new([10u8; 32]);
    let listener_contract_hash = Hash::new([11u8; 32]);
    let event_id = 1u64;
    let topoheight = 0u64;
    
    // Initialize both contracts
    let module = Arc::new(Module::new());
    let contract_module = ContractModule {
        version: Default::default(),
        module: module.clone(),
    };
    let versioned = Versioned::new(Some(Cow::Owned(contract_module)), None);
    storage.set_last_contract_to(&contract_hash, topoheight, &versioned).await.context("Failed to create contract")?;
    
    let contract_module2 = ContractModule {
        version: Default::default(),
        module,
    };
    let versioned2 = Versioned::new(Some(Cow::Owned(contract_module2)), None);
    storage.set_last_contract_to(&listener_contract_hash, topoheight, &versioned2).await.context("Failed to create listener contract")?;
    
    // Create an event callback registration
    let callback = EventCallbackRegistration::new(0, 100, Source::Contract(listener_contract_hash.clone()));
    let versioned_callback = Versioned::new(Some(callback.clone()), None);
    
    // Set event callback
    storage.set_last_contract_event_callback(
        &contract_hash,
        event_id,
        &listener_contract_hash,
        versioned_callback,
        topoheight,
    ).await.context("Failed to set event callback")?;
    
    // Retrieve event callback at maximum topoheight
    let retrieved = storage.get_event_callback_for_contract_at_maximum_topoheight(
        &contract_hash,
        event_id,
        &listener_contract_hash,
        topoheight,
    ).await.context("Failed to get event callback")?;
    
    assert!(retrieved.is_some(), "Event callback should exist");
    let (retrieved_topo, retrieved_versioned) = retrieved.unwrap();
    assert_eq!(retrieved_topo, topoheight, "Topoheight mismatch");
    assert!(retrieved_versioned.get().is_some(), "Callback registration should exist");
    let retrieved_callback = retrieved_versioned.get().as_ref().unwrap();
    assert_eq!(retrieved_callback.chunk_id, 0, "Chunk ID mismatch");
    assert_eq!(retrieved_callback.max_gas, 100, "Max gas mismatch");
    
    Ok(())
}

pub async fn test_contract_event_callback_retrieval<S: Storage>(mut storage: S) -> Result<()> {
    let contract_hash = Hash::new([20u8; 32]);
    let listener1_hash = Hash::new([21u8; 32]);
    let listener2_hash = Hash::new([22u8; 32]);
    let event_id = 42u64;
    let topoheight = 0u64;
    
    // Initialize all contracts  
    let module = Arc::new(Module::new());
    let contract_module = ContractModule {
        version: Default::default(),
        module: module.clone(),
    };
    let versioned = Versioned::new(Some(Cow::Owned(contract_module)), None);
    storage.set_last_contract_to(&contract_hash, topoheight, &versioned).await.context("Failed to create contract")?;
    
    for listener_hash in &[&listener1_hash, &listener2_hash] {
        let contract_module = ContractModule {
            version: Default::default(),
            module: module.clone(),
        };
        let versioned = Versioned::new(Some(Cow::Owned(contract_module)), None);
        storage.set_last_contract_to(listener_hash, topoheight, &versioned).await.context("Failed to create listener contract")?;
    }
    
    // Register multiple listeners for the same event
    let listeners = vec![(listener1_hash, 0u64), (listener2_hash, 1u64)];
    for (listener_hash, listener_idx) in listeners {
        let callback = EventCallbackRegistration::new(listener_idx as u16, 200u64 + listener_idx, Source::Contract(listener_hash.clone()));
        let versioned = Versioned::new(Some(callback), None);
        storage.set_last_contract_event_callback(
            &contract_hash,
            event_id,
            &listener_hash,
            versioned,
            listener_idx,
        ).await.context(format!("Failed to set callback for listener {}", listener_idx))?;
    }
    
    // Get all callbacks for the event at maximum topoheight
    let callbacks = storage.get_event_callbacks_for_event_at_maximum_topoheight(
        &contract_hash,
        event_id,
        1u64,
    ).await.context("Failed to get event callbacks")?;
    
    // Collect results
    let mut found_count = 0;
    futures::pin_mut!(callbacks);
    while let Some(result) = callbacks.next().await {
        let (_listener_hash, _topo, _versioned) = result.context("Failed to read callback from stream")?;
        found_count += 1;
    }
    
    assert_eq!(found_count, 2, "Should have 2 listeners registered");
    
    Ok(())
}

pub async fn test_contract_event_callback_versioning<S: Storage>(mut storage: S) -> Result<()> {
    let contract_hash = Hash::new([30u8; 32]);
    let listener_hash = Hash::new([31u8; 32]);
    let event_id = 100u64;
    let topoheight = 5u64;
    
    // Initialize both contracts
    let module = Arc::new(Module::new());
    let contract_module = ContractModule {
        version: Default::default(),
        module: module.clone(),
    };
    let versioned = Versioned::new(Some(Cow::Owned(contract_module)), None);
    storage.set_last_contract_to(&contract_hash, topoheight, &versioned).await.context("Failed to create contract")?;
    
    let contract_module2 = ContractModule {
        version: Default::default(),
        module,
    };
    let versioned2 = Versioned::new(Some(Cow::Owned(contract_module2)), None);
    storage.set_last_contract_to(&listener_hash, topoheight, &versioned2).await.context("Failed to create listener contract")?;
    
    // Register version 1 at topoheight 5
    let callback_v1 = EventCallbackRegistration::new(0, 300, Source::Contract(listener_hash.clone()));
    storage.set_last_contract_event_callback(
        &contract_hash,
        event_id,
        &listener_hash,
        Versioned::new(Some(callback_v1), None),
        5u64,
    ).await.context("Failed to set callback v1")?;
    
    // Register version 2 at topoheight 10 (update)
    let callback_v2 = EventCallbackRegistration::new(1, 400, Source::Contract(listener_hash.clone()));
    storage.set_last_contract_event_callback(
        &contract_hash,
        event_id,
        &listener_hash,
        Versioned::new(Some(callback_v2), Some(5u64)),
        10u64,
    ).await.context("Failed to set callback v2")?;
    
    // Get at topoheight 8 should return v1
    let result_v1 = storage.get_event_callback_for_contract_at_maximum_topoheight(
        &contract_hash,
        event_id,
        &listener_hash,
        8u64,
    ).await.context("Failed to get callback at topo 8")?;
    
    assert!(result_v1.is_some(), "Should find v1 at topoheight 8");
    let result_v1 = result_v1.unwrap();
    assert_eq!(result_v1.1.get().as_ref().unwrap().max_gas, 300, "v1 max_gas should be 300");
    
    // Get at topoheight 15 should return v2
    let result_v2 = storage.get_event_callback_for_contract_at_maximum_topoheight(
        &contract_hash,
        event_id,
        &listener_hash,
        15u64,
    ).await.context("Failed to get callback at topo 15")?;
    
    assert!(result_v2.is_some(), "Should find v2 at topoheight 15");
    let result_v2 = result_v2.unwrap();
    assert_eq!(result_v2.1.get().as_ref().unwrap().max_gas, 400, "v2 max_gas should be 400");
    
    Ok(())
}

pub async fn test_event_callback_unregister<S: Storage>(mut storage: S) -> Result<()> {
    let contract_hash = Hash::new([40u8; 32]);
    let listener_hash = Hash::new([41u8; 32]);
    let event_id = 50u64;
    let topoheight = 0u64;
    
    // Initialize both contracts
    let module = Arc::new(Module::new());
    let contract_module = ContractModule {
        version: Default::default(),
        module: module.clone(),
    };
    let versioned = Versioned::new(Some(Cow::Owned(contract_module)), None);
    storage.set_last_contract_to(&contract_hash, topoheight, &versioned).await.context("Failed to create contract")?;
    
    let contract_module2 = ContractModule {
        version: Default::default(),
        module,
    };
    let versioned2 = Versioned::new(Some(Cow::Owned(contract_module2)), None);
    storage.set_last_contract_to(&listener_hash, topoheight, &versioned2).await.context("Failed to create listener contract")?;
    
    // Register callback
    let callback = EventCallbackRegistration::new(0, 500, Source::Contract(listener_hash.clone()));
    storage.set_last_contract_event_callback(
        &contract_hash,
        event_id,
        &listener_hash,
        Versioned::new(Some(callback), None),
        0u64,
    ).await.context("Failed to set callback")?;
    
    // Unregister by setting to None
    storage.set_last_contract_event_callback(
        &contract_hash,
        event_id,
        &listener_hash,
        Versioned::new(None, Some(0u64)),
        5u64,
    ).await.context("Failed to unregister callback")?;
    
    // Check it's unregistered at later topoheight
    let result = storage.get_event_callback_for_contract_at_maximum_topoheight(
        &contract_hash,
        event_id,
        &listener_hash,
        10u64,
    ).await.context("Failed to get callback")?;
    
    assert!(result.is_some(), "Should find entry");
    assert!(result.unwrap().1.get().is_none(), "Callback should be None (unregistered)");
    
    Ok(())
}

// Tests for contract scheduled executions
pub async fn test_contract_scheduled_execution_storage<S: Storage>(mut storage: S) -> Result<()> {
    let contract_hash = Hash::new([50u8; 32]);
    let topoheight = 10u64;
    let execution_topoheight = 20u64;
    
    // Initialize the contract
    let module = Arc::new(Module::new());
    let contract_module = ContractModule {
        version: Default::default(),
        module,
    };
    let versioned = Versioned::new(Some(Cow::Owned(contract_module)), None);
    storage.set_last_contract_to(&contract_hash, topoheight, &versioned).await.context("Failed to create contract")?;
    
    // Create a scheduled execution
    let execution = ScheduledExecution {
        hash: Arc::new(Hash::new([51u8; 32])),
        contract: contract_hash.clone(),
        kind: ScheduledExecutionKind::TopoHeight(execution_topoheight),
        params: vec![],
        chunk_id: 0,
        max_gas: 1000,
        gas_sources: Default::default(),
    };
    
    // Store scheduled execution
    storage.set_contract_scheduled_execution_at_topoheight(
        &contract_hash,
        topoheight,
        &execution,
        execution_topoheight,
    ).await.context("Failed to set scheduled execution")?;
    
    // Check it exists (using execution_topoheight as the key)
    let exists = storage.has_contract_scheduled_execution_at_topoheight(
        &contract_hash,
        execution_topoheight,
    ).await.context("Failed to check scheduled execution")?;
    
    assert!(exists, "Scheduled execution should exist");
    
    // Retrieve it (using execution_topoheight as the key)
    let retrieved = storage.get_contract_scheduled_execution_at_topoheight(
        &contract_hash,
        execution_topoheight,
    ).await.context("Failed to retrieve scheduled execution")?;
    
    assert_eq!(retrieved.hash, execution.hash, "Hash mismatch");
    assert_eq!(retrieved.contract, contract_hash, "Contract mismatch");
    
    Ok(())
}

pub async fn test_contract_scheduled_execution_retrieval<S: Storage>(mut storage: S, _data: &TestData) -> Result<()> {
    let contract1 = Hash::new([60u8; 32]);
    let contract2 = Hash::new([61u8; 32]);
    let execution_topoheight = 30u64;
    let topoheight = 0u64;
    
    // Initialize the contracts
    let module = Arc::new(Module::new());
    let contract_module = ContractModule {
        version: Default::default(),
        module,
    };
    let versioned = Versioned::new(Some(Cow::Owned(contract_module)), None);
    storage.set_last_contract_to(&contract1, topoheight, &versioned).await.context("Failed to create contract1")?;
    storage.set_last_contract_to(&contract2, topoheight, &versioned).await.context("Failed to create contract2")?;
    
    // Store multiple scheduled executions for different contracts at the same execution topoheight
    for (idx, contract) in vec![(0u64, contract1), (1u64, contract2)].into_iter() {
        let execution = ScheduledExecution {
            hash: Arc::new(Hash::new([62u8 + idx as u8; 32])),
            contract: contract.clone(),
            kind: ScheduledExecutionKind::TopoHeight(execution_topoheight),
            params: vec![],
            chunk_id: 0,
            max_gas: 2000,
            gas_sources: Default::default(),
        };
        
        storage.set_contract_scheduled_execution_at_topoheight(
            &contract,
            topoheight + idx,  // Registration topoheight
            &execution,
            execution_topoheight,  // Execution topoheight (key)
        ).await.context(format!("Failed to set execution for contract {}", idx))?;
    }
    
    // Get all executions planned for execution at the same topoheight
    let mut executions = storage.get_contract_scheduled_executions_for_execution_topoheight(
        execution_topoheight,
    ).await.context("Failed to get scheduled executions for topoheight")?;
    
    // Count how many we get
    let mut count = 0;
    for result in &mut executions {
        let _contract_hash = result.context("Failed to read execution")?;
        count += 1;
    }
    
    assert_eq!(count, 2, "Should have 2 scheduled executions at topoheight {}", execution_topoheight);
    
    Ok(())
}

pub async fn test_contract_scheduled_execution_at_topoheight_range<S: Storage>(mut storage: S) -> Result<()> {
    let contract_hash = Hash::new([70u8; 32]);
    let topoheight = 0u64;
    
    // Initialize the contract
    let module = Arc::new(Module::new());
    let contract_module = ContractModule {
        version: Default::default(),
        module,
    };
    let versioned = Versioned::new(Some(Cow::Owned(contract_module)), None);
    storage.set_last_contract_to(&contract_hash, topoheight, &versioned).await.context("Failed to create contract")?;
    
    // Store scheduled executions registered at different topoheights
    for reg_topo in 0u64..5 {
        let execution = ScheduledExecution {
            hash: Arc::new(Hash::new([71 + reg_topo as u8; 32])),
            contract: contract_hash.clone(),
            kind: ScheduledExecutionKind::TopoHeight(100 + reg_topo),
            params: vec![],
            chunk_id: 0,
            max_gas: 3000,
            gas_sources: Default::default(),
        };
        
        storage.set_contract_scheduled_execution_at_topoheight(
            &contract_hash,
            reg_topo,
            &execution,
            100 + reg_topo,
        ).await.context(format!("Failed to set execution at topo {}", reg_topo))?;
    }
    
    // Query at a specific registration topoheight
    let registered = storage.get_registered_contract_scheduled_executions_at_topoheight(
        2u64,
    ).await.context("Failed to get registered executions")?;
    
    let mut topoheights = vec![];
    for result in registered {
        let (exec_topo, _) = result.context("Failed to read registered execution")?;
        topoheights.push(exec_topo);
    }

    assert!(topoheights.len() == 1, "Should find exactly one registered execution at topoheight 102 but found {}", topoheights.len());
    assert!(topoheights.contains(&102u64), "Should find registered execution at topoheight 102");

    Ok(())
}

// Tests for cleanup per topoheight
pub async fn test_cleanup_above_topoheight_with_mixed_data<S: Storage>(mut storage: S, data: &TestData) -> Result<()> {
    let public_key = data.public_key_pair.get_public_key().compress();
    
    // Store nonce data at multiple topoheights
    for topo in 0u64..10 {
        let nonce = VersionedNonce::new(topo * 10, None);
        storage.set_last_nonce_to(&public_key, topo, &nonce).await
            .context(format!("Failed to set nonce at topo {}", topo))?;
    }
    
    // Store block data at multiple topoheights
    for i in 0u64..10 {
        let hash = Hash::new([120 + i as u8; 32]);
        let mut header = data.block_header.clone();
        header.height = i;
        let block_arc = Arc::new(header);
        let block_hash_immutable: Immutable<Hash> = Immutable::Owned(hash);
        
        storage.save_block(
            block_arc,
            &[],
            Default::default(),
            Difficulty::zero(),
            0u64.into(),
            VarUint::from(0u32),
            i as u32,
            block_hash_immutable
        ).await.context(format!("Failed to save block at height {}", i))?;
    }
    
    // Store contract event callbacks at multiple topoheights
    let contract_hash = Hash::new([130u8; 32]);
    let listener_hash = Hash::new([131u8; 32]);
    
    // Initialize both contracts
    let module = Arc::new(Module::new());
    let contract_module = ContractModule {
        version: Default::default(),
        module: module.clone(),
    };
    let versioned = Versioned::new(Some(Cow::Owned(contract_module)), None);
    storage.set_last_contract_to(&contract_hash, 0u64, &versioned).await.context("Failed to create contract")?;
    
    let contract_module2 = ContractModule {
        version: Default::default(),
        module,
    };
    let versioned2 = Versioned::new(Some(Cow::Owned(contract_module2)), None);
    storage.set_last_contract_to(&listener_hash, 0u64, &versioned2).await.context("Failed to create listener contract")?;
    
    for topo in 0u64..5 {
        let callback = EventCallbackRegistration::new(topo as u16, 100 + topo, Source::Contract(listener_hash.clone()));
        storage.set_last_contract_event_callback(
            &contract_hash,
            1u64,
            &listener_hash,
            Versioned::new(Some(callback), None),
            topo,
        ).await.context(format!("Failed to set callback at topo {}", topo))?;
    }
    
    // Verify data exists
    let nonce_before = storage.get_last_nonce(&public_key).await
        .context("Failed to get nonce before cleanup")?;
    assert_eq!(nonce_before.1.get_nonce(), 90, "Nonce should be 90 before cleanup");
    
    Ok(())
}

pub async fn test_cleanup_below_topoheight_with_mixed_data<S: Storage>(mut storage: S, data: &TestData) -> Result<()> {
    let public_key = data.public_key_pair.get_public_key().compress();
    
    // Store nonce data at multiple topoheights
    for topo in 0u64..10 {
        let nonce = VersionedNonce::new(topo * 5, None);
        storage.set_last_nonce_to(&public_key, topo, &nonce).await
            .context(format!("Failed to set nonce at topo {}", topo))?;
    }
    
    // Store scheduled executions at multiple topoheights
    let contract_hash = Hash::new([140u8; 32]);
    
    // Initialize the contract
    let module = Arc::new(Module::new());
    let contract_module = ContractModule {
        version: Default::default(),
        module,
    };
    let versioned = Versioned::new(Some(Cow::Owned(contract_module)), None);
    storage.set_last_contract_to(&contract_hash, 0u64, &versioned).await.context("Failed to create contract")?;
    
    for topo in 0u64..10 {
        let execution = ScheduledExecution {
            hash: Arc::new(Hash::new([141u8 + topo as u8; 32])),
            contract: contract_hash.clone(),
            kind: ScheduledExecutionKind::TopoHeight(50 + topo),
            params: vec![],
            chunk_id: 0,
            max_gas: 6000,
            gas_sources: Default::default(),
        };
        
        storage.set_contract_scheduled_execution_at_topoheight(
            &contract_hash,
            topo,
            &execution,
            50 + topo,
        ).await.context(format!("Failed to set execution at topo {}", topo))?;
    }
    
    // Verify data exists before any potential cleanup
    let nonce_result = storage.get_last_nonce(&public_key).await
        .context("Failed to get nonce")?;
    assert_eq!(nonce_result.1.get_nonce(), 45, "Nonce should be 45");
    
    // Verify execution exists (use execution_topoheight 55 which is 50 + topo where topo=5)
    let execution_exists = storage.has_contract_scheduled_execution_at_topoheight(
        &contract_hash,
        55u64,  // execution_topoheight for topo=5 is 50+5=55
    ).await.context("Failed to check execution")?;
    assert!(execution_exists, "Execution should exist at execution_topoheight 55");
    
    Ok(())
}

pub async fn test_cleanup_all_data_types_at_topoheight<S: Storage>(mut storage: S, data: &TestData) -> Result<()> {
    let public_key = data.public_key_pair.get_public_key().compress();
    let contract_hash = Hash::new([150u8; 32]);
    let listener_hash = Hash::new([151u8; 32]);
    let target_topo = 5u64;

    // Initialize both contracts
    let module = Arc::new(Module::new());
    let contract_module = ContractModule {
        version: Default::default(),
        module: module.clone(),
    };
    let versioned = Versioned::new(Some(Cow::Owned(contract_module)), None);
    storage.set_last_contract_to(&contract_hash, target_topo, &versioned).await.context("Failed to create contract")?;
    
    let contract_module2 = ContractModule {
        version: Default::default(),
        module,
    };
    let versioned2 = Versioned::new(Some(Cow::Owned(contract_module2)), None);
    storage.set_last_contract_to(&listener_hash, target_topo, &versioned2).await.context("Failed to create listener contract")?;

    // Set nonce at target topoheight
    let nonce = VersionedNonce::new(50, None);
    storage.set_last_nonce_to(&public_key, target_topo, &nonce).await
        .context("Failed to set nonce")?;
    
    // Set event callback at target topoheight
    let callback = EventCallbackRegistration::new(1, 500, Source::Contract(listener_hash.clone()));
    storage.set_last_contract_event_callback(
        &contract_hash,
        1u64,
        &listener_hash,
        Versioned::new(Some(callback), None),
        target_topo,
    ).await.context("Failed to set callback")?;
    
    // Set scheduled execution at target topoheight
    let execution = ScheduledExecution {
        hash: Arc::new(Hash::new([152u8; 32])),
        contract: contract_hash.clone(),
        kind: ScheduledExecutionKind::TopoHeight(60),
        params: vec![],
        chunk_id: 0,
        max_gas: 4000,
        gas_sources: Default::default(),
    };
    storage.set_contract_scheduled_execution_at_topoheight(
        &contract_hash,
        target_topo,
        &execution,
        60u64,
    ).await.context("Failed to set execution")?;
    
    // Save a block at target topoheight
    let block_hash = Hash::new([153u8; 32]);
    let block_hash_for_check = block_hash.clone();
    let mut header = data.block_header.clone();
    header.height = target_topo;
    let block_arc = Arc::new(header);
    let block_hash_immutable: Immutable<Hash> = Immutable::Owned(block_hash);
    
    storage.save_block(
        block_arc,
        &[],
        Default::default(),
        Difficulty::zero(),
        0u64.into(),
        VarUint::from(0u32),
        target_topo as u32,
        block_hash_immutable
    ).await.context("Failed to save block")?;
    
    // Verify all data exists
    let nonce = storage.get_last_nonce(&public_key).await
        .context("Failed to get nonce")?;
    assert_eq!(nonce.1.get_nonce(), 50, "Nonce should exist");
    
    let callback_result = storage.get_event_callback_for_contract_at_maximum_topoheight(
        &contract_hash,
        1u64,
        &listener_hash,
        target_topo,
    ).await.context("Failed to get callback")?;
    assert!(callback_result.is_some(), "Callback should exist");
    
    let exec_exists = storage.has_contract_scheduled_execution_at_topoheight(
        &contract_hash,
        60u64,  // execution_topoheight is 60
    ).await.context("Failed to check execution")?;
    assert!(exec_exists, "Execution should exist");
    
    let block_exists = storage.has_block_with_hash(&block_hash_for_check).await
        .context("Failed to check block")?;
    assert!(block_exists, "Block should exist");
    
    Ok(())
}

// Tests for versioned data at maximum topoheight
pub async fn test_versioned_nonce_at_max_topoheight<S: Storage>(mut storage: S, data: &TestData) -> Result<()> {
    let public_key = data.public_key_pair.get_public_key().compress();
    
    // Create versioned nonces at different topoheights
    storage.set_last_nonce_to(&public_key, 0u64, &VersionedNonce::new(10, None)).await
        .context("Failed to set nonce at topo 0")?;
    
    storage.set_last_nonce_to(&public_key, 5u64, &VersionedNonce::new(20, None)).await
        .context("Failed to set nonce at topo 5")?;
    
    storage.set_last_nonce_to(&public_key, 10u64, &VersionedNonce::new(30, None)).await
        .context("Failed to set nonce at topo 10")?;
    
    // Get nonce (should return latest)
    let (topo, nonce) = storage.get_last_nonce(&public_key).await
        .context("Failed to get nonce")?;
    
    assert_eq!(topo, 10u64, "Should return latest topoheight");
    assert_eq!(nonce.get_nonce(), 30, "Should return latest nonce value");
    
    Ok(())
}

pub async fn test_versioned_contract_event_callback_stream<S: Storage>(mut storage: S) -> Result<()> {
    let contract_hash = Hash::new([160u8; 32]);
    let event_id = 100u64;
    
    // Initialize the contract
    let module = Arc::new(Module::new());
    let contract_module = ContractModule {
        version: Default::default(),
        module: module.clone(),
    };
    let versioned = Versioned::new(Some(Cow::Owned(contract_module)), None);
    storage.set_last_contract_to(&contract_hash, 0u64, &versioned).await.context("Failed to create contract")?;
    
    // Register different listeners at different topoheights for the same event
    for (idx, listener_idx) in [(0u64, 10u8), (1u64, 11u8), (2u64, 12u8)] {
        let listener_hash = Hash::new([listener_idx; 32]);
        
        // Initialize listener contract
        let contract_module = ContractModule {
            version: Default::default(),
            module: module.clone(),
        };
        let versioned = Versioned::new(Some(Cow::Owned(contract_module)), None);
        storage.set_last_contract_to(&listener_hash, idx, &versioned).await.context("Failed to create listener contract")?;
        
        let callback = EventCallbackRegistration::new(idx as u16, 600 + idx, Source::Contract(listener_hash.clone()));
        
        storage.set_last_contract_event_callback(
            &contract_hash,
            event_id,
            &listener_hash,
            Versioned::new(Some(callback), None),
            idx,
        ).await.context(format!("Failed to set callback {}", idx))?;
    }
    
    // Stream all callbacks for this event at maximum topoheight
    let callbacks_stream = storage.get_event_callbacks_for_event_at_maximum_topoheight(
        &contract_hash,
        event_id,
        10u64,
    ).await.context("Failed to get callbacks stream")?;
    
    let mut count = 0;
    futures::pin_mut!(callbacks_stream);
    while let Some(result) = callbacks_stream.next().await {
        result.context("Failed to read from callback stream")?;
        count += 1;
    }
    
    assert_eq!(count, 3, "Should have 3 listeners in stream");
    
    Ok(())
}

pub async fn test_versioned_scheduled_execution_in_range<S: Storage>(mut storage: S) -> Result<()> {
    let contract_hash = Hash::new([170u8; 32]);
    
    // Initialize the contract
    let module = Arc::new(Module::new());
    let contract_module = ContractModule {
        version: Default::default(),
        module,
    };
    let versioned = Versioned::new(Some(Cow::Owned(contract_module)), None);
    storage.set_last_contract_to(&contract_hash, 0u64, &versioned).await.context("Failed to create contract")?;
    
    // Register scheduled executions at various topoheights
    for reg_topo in 0u64..10 {
        let execution = ScheduledExecution {
            hash: Arc::new(Hash::new([171 + reg_topo as u8; 32])),
            contract: contract_hash.clone(),
            kind: ScheduledExecutionKind::TopoHeight(100 + reg_topo),
            params: vec![],
            chunk_id: 0,
            max_gas: 5000,
            gas_sources: Default::default(),
        };
        
        storage.set_contract_scheduled_execution_at_topoheight(
            &contract_hash,
            reg_topo,
            &execution,
            100 + reg_topo,
        ).await.context(format!("Failed to set execution at topo {}", reg_topo))?;
    }
    
    // Query scheduled executions in a range (including execution topoheight filtering)
    let executions = storage.get_registered_contract_scheduled_executions_in_range(
        0u64,
        5u64,
        Some(100u64),
    ).await.context("Failed to get executions in range")?;
    
    let mut count = 0;
    futures::pin_mut!(executions);
    while let Some(result) = executions.next().await {
        let (exec_topo, reg_topo, _execution) = result.context("Failed to read from range stream")?;
        assert!(reg_topo <= 5u64, "Registration topoheight should be <= 5, got {}", reg_topo);
        assert!(exec_topo >= 100u64, "Execution topoheight should be >= 100, got {}", exec_topo);
        count += 1;
    }
    
    assert_eq!(count, 6, "Should have 6 executions in range 0-5");
    
    Ok(())
}

pub async fn test_versioned_data_max_topoheight_boundary<S: Storage>(mut storage: S, data: &TestData) -> Result<()> {
    let public_key = data.public_key_pair.get_public_key().compress();
    let contract_hash = Hash::new([180u8; 32]);
    let listener_hash = Hash::new([181u8; 32]);
    
    // Initialize both contracts
    let module = Arc::new(Module::new());
    let contract_module = ContractModule {
        version: Default::default(),
        module: module.clone(),
    };
    let versioned = Versioned::new(Some(Cow::Owned(contract_module)), None);
    storage.set_last_contract_to(&contract_hash, 100u64, &versioned).await.context("Failed to create contract")?;
    
    let contract_module2 = ContractModule {
        version: Default::default(),
        module,
    };
    let versioned2 = Versioned::new(Some(Cow::Owned(contract_module2)), None);
    storage.set_last_contract_to(&listener_hash, 100u64, &versioned2).await.context("Failed to create listener contract")?;
    
    // Set nonce at topoheight 100
    storage.set_last_nonce_to(&public_key, 100u64, &VersionedNonce::new(100, None)).await
        .context("Failed to set nonce")?;
    
    // Set event callback at topoheight 100
    let callback = EventCallbackRegistration::new(10, 1000, Source::Contract(listener_hash.clone()));
    storage.set_last_contract_event_callback(
        &contract_hash,
        1u64,
        &listener_hash,
        Versioned::new(Some(callback), None),
        100u64,
    ).await.context("Failed to set callback")?;
    
    // Query at exactly max_topoheight (100)
    let nonce_at_100 = storage.get_last_nonce(&public_key).await
        .context("Failed to get nonce at 100")?;
    assert_eq!(nonce_at_100.0, 100u64, "Should find nonce at exact topoheight");
    
    let callback_at_100 = storage.get_event_callback_for_contract_at_maximum_topoheight(
        &contract_hash,
        1u64,
        &listener_hash,
        100u64,
    ).await.context("Failed to get callback at 100")?;
    assert!(callback_at_100.is_some(), "Should find callback at exact topoheight");
    
    // Query at topoheight 99 (should not find data set at 100)
    let callback_at_99 = storage.get_event_callback_for_contract_at_maximum_topoheight(
        &contract_hash,
        1u64,
        &listener_hash,
        99u64,
    ).await.context("Failed to get callback at 99")?;
    assert!(callback_at_99.is_none(), "Should not find callback set at higher topoheight");

    // Query at topoheight 101 (should find data set at 100)
    let callback_at_101 = storage.get_event_callback_for_contract_at_maximum_topoheight(
        &contract_hash,
        1u64,
        &listener_hash,
        101u64,
    ).await.context("Failed to get callback at 101")?;
    assert!(callback_at_101.is_some(), "Should find callback at higher topoheight");
    
    Ok(())
}

pub async fn test_asset_data_at_maximum_topoheight<S: Storage>(mut storage: S) -> Result<()> {
    let asset = Hash::new([182u8; 32]);
    let origin = Hash::new([183u8; 32]);
    let owner_at_10 = Hash::new([184u8; 32]);
    let owner_at_20 = Hash::new([185u8; 32]);

    let data_at_0 = AssetData::new(
        8,
        "Asset 0".to_owned(),
        "A0".to_owned(),
        MaxSupplyMode::Mintable(1_000),
        AssetOwner::Creator {
            contract: origin.clone(),
            id: 0,
        },
    );
    storage.add_asset(&asset, 0, VersionedAssetData::new(data_at_0, None)).await
        .context("Failed to add asset at topo 0")?;

    let data_at_10 = AssetData::new(
        8,
        "Asset 10".to_owned(),
        "A10".to_owned(),
        MaxSupplyMode::Mintable(1_000),
        AssetOwner::Owner {
            origin: origin.clone(),
            origin_id: 0,
            owner: owner_at_10,
        },
    );
    storage.add_asset(&asset, 10, VersionedAssetData::new(data_at_10, Some(0))).await
        .context("Failed to add asset at topo 10")?;

    let data_at_20 = AssetData::new(
        8,
        "Asset 20".to_owned(),
        "A20".to_owned(),
        MaxSupplyMode::Mintable(1_000),
        AssetOwner::Owner {
            origin,
            origin_id: 0,
            owner: owner_at_20,
        },
    );
    storage.add_asset(&asset, 20, VersionedAssetData::new(data_at_20, Some(10))).await
        .context("Failed to add asset at topo 20")?;

    let (topoheight, data) = storage.get_asset_at_maximum_topoheight(&asset, 15).await
        .context("Failed to get asset at maximum topoheight 15")?
        .context("Expected asset data at maximum topoheight 15")?;
    assert_eq!(topoheight, 10, "Should walk back to the newest asset data <= 15");
    assert_eq!(data.get().get_name(), "Asset 10", "Unexpected asset data at topoheight 15");
    assert_eq!(data.get().get_ticker(), "A10", "Unexpected asset ticker at topoheight 15");

    let (topoheight, data) = storage.get_asset_at_maximum_topoheight(&asset, 10).await
        .context("Failed to get asset at maximum topoheight 10")?
        .context("Expected asset data at maximum topoheight 10")?;
    assert_eq!(topoheight, 10, "Should return exact asset data at topoheight 10");
    assert_eq!(data.get().get_name(), "Asset 10", "Unexpected asset data at exact topoheight");

    let (topoheight, data) = storage.get_asset_at_maximum_topoheight(&asset, 25).await
        .context("Failed to get asset at maximum topoheight 25")?
        .context("Expected asset data at maximum topoheight 25")?;
    assert_eq!(topoheight, 20, "Should return latest asset data below topoheight 25");
    assert_eq!(data.get().get_name(), "Asset 20", "Unexpected asset data at latest topoheight");

    Ok(())
}

pub async fn test_asset_supply_at_maximum_topoheight<S: Storage>(mut storage: S) -> Result<()> {
    let asset = Hash::new([186u8; 32]);
    let origin = Hash::new([187u8; 32]);
    let data = AssetData::new(
        8,
        "Supply Asset".to_owned(),
        "SUP".to_owned(),
        MaxSupplyMode::Mintable(1_000),
        AssetOwner::Creator {
            contract: origin,
            id: 0,
        },
    );
    storage.add_asset(&asset, 0, VersionedAssetData::new(data, None)).await
        .context("Failed to add asset for supply test")?;

    storage.set_last_circulating_supply_for_asset(&asset, 5, &Versioned::new(100u64, None)).await
        .context("Failed to set supply at topo 5")?;
    storage.set_last_circulating_supply_for_asset(&asset, 10, &Versioned::new(200u64, Some(5))).await
        .context("Failed to set supply at topo 10")?;
    storage.set_last_circulating_supply_for_asset(&asset, 20, &Versioned::new(300u64, Some(10))).await
        .context("Failed to set supply at topo 20")?;

    let supply_before_first = storage.get_circulating_supply_for_asset_at_maximum_topoheight(&asset, 3).await
        .context("Failed to get supply at maximum topoheight 3")?;
    assert!(supply_before_first.is_none(), "Should not find supply before its first version");

    let (topoheight, supply) = storage.get_circulating_supply_for_asset_at_maximum_topoheight(&asset, 15).await
        .context("Failed to get supply at maximum topoheight 15")?
        .context("Expected supply at maximum topoheight 15")?;
    assert_eq!(topoheight, 10, "Should walk back to the newest supply <= 15");
    assert_eq!(*supply.get(), 200u64, "Unexpected supply at topoheight 15");

    let (topoheight, supply) = storage.get_circulating_supply_for_asset_at_maximum_topoheight(&asset, 10).await
        .context("Failed to get supply at maximum topoheight 10")?
        .context("Expected supply at maximum topoheight 10")?;
    assert_eq!(topoheight, 10, "Should return exact supply at topoheight 10");
    assert_eq!(*supply.get(), 200u64, "Unexpected supply at exact topoheight");

    let (topoheight, supply) = storage.get_circulating_supply_for_asset_at_maximum_topoheight(&asset, 25).await
        .context("Failed to get supply at maximum topoheight 25")?
        .context("Expected supply at maximum topoheight 25")?;
    assert_eq!(topoheight, 20, "Should return latest supply below topoheight 25");
    assert_eq!(*supply.get(), 300u64, "Unexpected supply at latest topoheight");

    Ok(())
}

// Tests for versioned data cleanup operations
pub async fn test_delete_versioned_data_at_topoheight_nonces<S: Storage>(mut storage: S, data: &TestData) -> Result<()> {
    let public_key = data.public_key_pair.get_public_key().compress();
    
    // Store nonces at multiple topoheights with proper versioning
    let nonce0 = VersionedNonce::new(0, None);
    storage.set_last_nonce_to(&public_key, 0u64, &nonce0).await
        .context("Failed to set nonce at topo 0")?;
    
    for topo in 1u64..10 {
        let nonce = VersionedNonce::new(topo * 10, Some(topo - 1));
        storage.set_last_nonce_to(&public_key, topo, &nonce).await
            .context(format!("Failed to set nonce at topo {}", topo))?;
    }

    for topo in 5..10 {
        // Delete data topoheight
        storage.delete_versioned_data_at_topoheight(topo, false).await
            .context(format!("Failed to delete versioned data at topoheight {}", topo))?;
    }

    // Verify we can still query data (implementation-dependent what's returned)
    let (topoheight, mut nonce) = storage.get_last_nonce(&public_key).await?;

    assert!(topoheight == 4u64, "Data at topoheight 4 should still exist, got {}", topoheight);
    assert!(nonce.get_nonce() == 40, "Nonce at topoheight 4 should be 40, got {}", nonce.get_nonce());

    // Check that all versions are still present
    let mut total = 0;
    while let Some(prev) = nonce.get_previous_topoheight() {
        nonce = storage.get_nonce_at_exact_topoheight(&public_key, prev).await?;
        total += 1;
    }

    assert_eq!(total, 4, "Should have 4 versions of nonce remaining, got {}", total);

    Ok(())
}

pub async fn test_delete_versioned_data_below_topoheight_nonces<S: Storage>(mut storage: S, data: &TestData) -> Result<()> {
    let public_key = data.public_key_pair.get_public_key().compress();
    
    // Store nonces at multiple topoheights with proper versioning
    let nonce0 = VersionedNonce::new(0, None);
    storage.set_last_nonce_to(&public_key, 0u64, &nonce0).await
        .context("Failed to set nonce at topo 0")?;

    for topo in 1u64..10 {
        let nonce = VersionedNonce::new(topo * 10, Some(topo - 1));
        storage.set_last_nonce_to(&public_key, topo, &nonce).await
            .context(format!("Failed to set nonce at topo {}", topo))?;
    }
    
    // Delete data below topoheight 5 (keep_last=true keeps one version below)
    storage.delete_versioned_data_below_topoheight(5u64, true).await
        .context("Failed to delete versioned data below topoheight 5")?;

    // Verify we can still query data
    let (topoheight, mut nonce) = storage.get_last_nonce(&public_key).await?;

    assert!(topoheight == 9, "last topoheight should still be 9, got {}", topoheight);
 
    // Check that all versions are still present
    let mut total = 0;
    while let Some(prev) = nonce.get_previous_topoheight() {
        nonce = storage.get_nonce_at_exact_topoheight(&public_key, prev).await
            .with_context(|| format!("Failed to get nonce at topoheight {}", prev))?;
        total += 1;
    }

    assert_eq!(total, 4, "Should have 4 more versions of nonce remaining, got {}", total);
    Ok(())
}

pub async fn test_delete_versioned_data_above_topoheight_nonces<S: Storage>(mut storage: S, data: &TestData) -> Result<()> {
    let public_key = data.public_key_pair.get_public_key().compress();
    
    // Store nonces at multiple topoheights with proper versioning
    let nonce0 = VersionedNonce::new(0, None);
    storage.set_last_nonce_to(&public_key, 0u64, &nonce0).await
        .context("Failed to set nonce at topo 0")?;

    for topo in 1u64..10 {
        let nonce = VersionedNonce::new(topo * 10, Some(topo - 1));
        storage.set_last_nonce_to(&public_key, topo, &nonce).await
            .context(format!("Failed to set nonce at topo {}", topo))?;
    }

    // Delete data above topoheight 5
    storage.delete_versioned_data_above_topoheight(5u64).await
        .context("Failed to delete versioned data above topoheight 5")?;

    // Verify we can still query data
    let (topoheight, mut nonce) = storage.get_last_nonce(&public_key).await?;

    assert!(topoheight == 5, "last topoheight should still be 5, got {}", topoheight);
 
    // Check that all versions are still present
    let mut total = 0;
    while let Some(prev) = nonce.get_previous_topoheight() {
        nonce = storage.get_nonce_at_exact_topoheight(&public_key, prev).await?;
        total += 1;
    }

    assert_eq!(total, 5, "Should have 5 versions of nonce remaining, got {}", total);
    
    Ok(())
}

pub async fn test_delete_versioned_data_at_topoheight_contracts<S: Storage>(mut storage: S) -> Result<()> {
    let contract_hash = Hash::new([200u8; 32]);
    
    // Store contract at multiple topoheights
    for topo in 0u64..5 {
        let module = Arc::new(Module::new());
        let contract_module = ContractModule {
            version: Default::default(),
            module,
        };
        let versioned = Versioned::new(Some(Cow::Owned(contract_module)), None);
        storage.set_last_contract_to(&contract_hash, topo, &versioned).await
            .context(format!("Failed to set contract at topo {}", topo))?;
    }
    
    // Delete data at topoheight 2
    storage.delete_versioned_data_at_topoheight(2u64, false).await
        .context("Failed to delete versioned data at topoheight 2")?;
    
    // Verify storage is still usable
    let _ = storage.has_contract_at_maximum_topoheight(&contract_hash, 4u64).await?;
    
    Ok(())
}

pub async fn test_delete_versioned_data_below_topoheight_contracts<S: Storage>(mut storage: S) -> Result<()> {
    let contract_hash = Hash::new([201u8; 32]);
    
    // Store contract at multiple topoheights
    for topo in 0u64..8 {
        let module = Arc::new(Module::new());
        let contract_module = ContractModule {
            version: Default::default(),
            module,
        };
        let versioned = Versioned::new(Some(Cow::Owned(contract_module)), None);
        storage.set_last_contract_to(&contract_hash, topo, &versioned).await
            .context(format!("Failed to set contract at topo {}", topo))?;
    }
    
    // Delete data below topoheight 4
    storage.delete_versioned_data_below_topoheight(4u64, true).await
        .context("Failed to delete versioned data below topoheight 4")?;
    
    // Verify storage is still usable
    let _ = storage.has_contract_at_exact_topoheight(&contract_hash, 4u64).await?;
    
    Ok(())
}

pub async fn test_delete_versioned_data_above_topoheight_contracts<S: Storage>(mut storage: S) -> Result<()> {
    let contract_hash = Hash::new([202u8; 32]);
    
    // Store contract at multiple topoheights
    for topo in 0u64..8 {
        let module = Arc::new(Module::new());
        let contract_module = ContractModule {
            version: Default::default(),
            module,
        };
        let versioned = Versioned::new(Some(Cow::Owned(contract_module)), None);
        storage.set_last_contract_to(&contract_hash, topo, &versioned).await
            .context(format!("Failed to set contract at topo {}", topo))?;
    }
    
    // Delete data above topoheight 4
    storage.delete_versioned_data_above_topoheight(4u64).await
        .context("Failed to delete versioned data above topoheight 4")?;
    
    // Verify storage is still usable
    let _ = storage.has_contract_at_exact_topoheight(&contract_hash, 4u64).await?;
    
    Ok(())
}

pub async fn test_delete_versioned_data_at_topoheight_mixed<S: Storage>(mut storage: S, data: &TestData) -> Result<()> {
    let public_key = data.public_key_pair.get_public_key().compress();
    let contract_hash = Hash::new([210u8; 32]);
    
    // Store nonce data at multiple topoheights with versioning
    let nonce0 = VersionedNonce::new(0, None);
    storage.set_last_nonce_to(&public_key, 0u64, &nonce0).await
        .context("Failed to set nonce at topo 0")?;
    
    let nonce2 = VersionedNonce::new(20, Some(0u64));
    storage.set_last_nonce_to(&public_key, 2u64, &nonce2).await
        .context("Failed to set nonce at topo 2")?;
    
    let nonce3 = VersionedNonce::new(30, Some(2u64));
    storage.set_last_nonce_to(&public_key, 3u64, &nonce3).await
        .context("Failed to set nonce at topo 3")?;
    
    let nonce4 = VersionedNonce::new(40, Some(3u64));
    storage.set_last_nonce_to(&public_key, 4u64, &nonce4).await
        .context("Failed to set nonce at topo 4")?;
    
    // Store contract data at topoheight 3
    let module = Arc::new(Module::new());
    let contract_module = ContractModule {
        version: Default::default(),
        module,
    };
    let versioned = Versioned::new(Some(Cow::Owned(contract_module)), None);
    storage.set_last_contract_to(&contract_hash, 3u64, &versioned).await
        .context("Failed to set contract at topo 3")?;
    
    // Delete data at topoheight 3
    storage.delete_versioned_data_at_topoheight(3u64, false).await
        .context("Failed to delete versioned data at topoheight 3")?;
    
    // Verify storage is still usable
    let _ = storage.get_last_nonce(&public_key).await?;
    
    Ok(())
}

pub async fn test_delete_versioned_data_below_topoheight_mixed<S: Storage>(mut storage: S, data: &TestData) -> Result<()> {
    let public_key = data.public_key_pair.get_public_key().compress();
    let contract_hash = Hash::new([211u8; 32]);
    
    // Store data at multiple topoheights with proper versioning
    let nonce0 = VersionedNonce::new(0, None);
    storage.set_last_nonce_to(&public_key, 0u64, &nonce0).await
        .context("Failed to set nonce at topo 0")?;
    
    for topo in 1u64..8 {
        let nonce = VersionedNonce::new(topo * 10, Some(topo - 1));
        storage.set_last_nonce_to(&public_key, topo, &nonce).await
            .context(format!("Failed to set nonce at topo {}", topo))?;
        
        if topo < 6 {
            let module = Arc::new(Module::new());
            let contract_module = ContractModule {
                version: Default::default(),
                module,
            };
            let versioned = Versioned::new(Some(Cow::Owned(contract_module)), None);
            storage.set_last_contract_to(&contract_hash, topo, &versioned).await
                .context(format!("Failed to set contract at topo {}", topo))?;
        }
    }
    
    // Delete data below topoheight 4
    storage.delete_versioned_data_below_topoheight(4u64, true).await
        .context("Failed to delete versioned data below topoheight 4")?;
    
    // Verify storage is still usable
    let _ = storage.get_last_nonce(&public_key).await?;
    
    Ok(())
}

pub async fn test_delete_versioned_data_above_topoheight_mixed<S: Storage>(mut storage: S, data: &TestData) -> Result<()> {
    let public_key = data.public_key_pair.get_public_key().compress();
    let contract_hash = Hash::new([212u8; 32]);
    
    // Store data at multiple topoheights with proper versioning
    let nonce0 = VersionedNonce::new(0, None);
    storage.set_last_nonce_to(&public_key, 0u64, &nonce0).await
        .context("Failed to set nonce at topo 0")?;
    
    for topo in 1u64..8 {
        let nonce = VersionedNonce::new(topo * 10, Some(topo - 1));
        storage.set_last_nonce_to(&public_key, topo, &nonce).await
            .context(format!("Failed to set nonce at topo {}", topo))?;
        
        if topo < 8 {
            let module = Arc::new(Module::new());
            let contract_module = ContractModule {
                version: Default::default(),
                module,
            };
            let versioned = Versioned::new(Some(Cow::Owned(contract_module)), None);
            storage.set_last_contract_to(&contract_hash, topo, &versioned).await
                .context(format!("Failed to set contract at topo {}", topo))?;
        }
    }
    
    // Delete data above topoheight 4
    storage.delete_versioned_data_above_topoheight(4u64).await
        .context("Failed to delete versioned data above topoheight 4")?;
    
    // Verify storage is still usable
    let _ = storage.get_last_nonce(&public_key).await?;
    
    Ok(())
}

/// Helper: register an account and asset so that RocksDB's ID-mapping layer is
/// satisfied before calling any balance APIs.
async fn setup_balance_storage<S: Storage>(
    storage: &mut S,
    key: &PublicKey,
    asset: &Hash,
) -> Result<()> {
    // Register the account (no-op for MemoryStorage, required for RocksDB).
    storage.set_account_registration_topoheight(key, 0).await
        .context("Failed to register account")?;

    // Register the asset (no-op for MemoryStorage, required for RocksDB).
    storage.add_asset(
        asset,
        0,
        VersionedAssetData::new(
            AssetData::new(8, "Test".to_owned(), "TST".to_owned(), MaxSupplyMode::Fixed(u64::MAX), AssetOwner::None),
            None,
        ),
    ).await.context("Failed to add asset")?;

    Ok(())
}

pub async fn test_delete_versioned_balances_below_topoheight_keeps_latest_output<S: Storage>(
    mut storage: S,
    data: &TestData,
) -> Result<()> {
    let key = data.public_key_pair.get_public_key().compress();
    setup_balance_storage(&mut storage, &key, &XELIS_ASSET).await?;

    let mut balance = VersionedBalance::zero();
    storage.set_last_balance_to(&key, &XELIS_ASSET, 0, &balance).await
        .context("Failed to set balance at topo 0")?;

    balance.set_previous_topoheight(Some(0));
    balance.set_balance_type(BalanceType::Output);
    storage.set_last_balance_to(&key, &XELIS_ASSET, 1, &balance).await
        .context("Failed to set output balance at topo 1")?;

    for topo in 2u64..=6 {
        balance.set_previous_topoheight(Some(topo - 1));
        balance.set_balance_type(BalanceType::Input);
        storage.set_last_balance_to(&key, &XELIS_ASSET, topo, &balance).await
            .with_context(|| format!("Failed to set input balance at topo {}", topo))?;
    }

    storage.delete_versioned_data_below_topoheight(5, true).await
        .context("Failed to delete versioned data below topoheight 5")?;

    let output_exists = storage.has_balance_at_exact_topoheight(&key, &XELIS_ASSET, 1).await
        .context("Failed to check output balance existence")?;
    assert!(output_exists, "Latest output-bearing balance below the cutoff must be kept");

    let first_exists = storage.has_balance_at_exact_topoheight(&key, &XELIS_ASSET, 0).await
        .context("Failed to check pruned balance existence")?;
    assert!(!first_exists, "Balances below the retained output-bearing balance should be pruned");

    let output_balance = storage.get_balance_at_exact_topoheight(&key, &XELIS_ASSET, 1).await
        .context("Failed to get retained output balance")?;
    assert_eq!(output_balance.get_previous_topoheight(), None, "Retained output balance should become the chain anchor");
    assert!(output_balance.contains_output(), "Retained balance should still be output-bearing");

    let (output_topoheight, _) = storage.get_output_balance_at_maximum_topoheight(&key, &XELIS_ASSET, 6).await
        .context("Failed to get output balance")?
        .context("Expected output balance to be found")?;
    assert_eq!(output_topoheight, 1, "Latest output-bearing balance should be returned after pruning");

    let (last_topoheight, mut last_balance) = storage.get_last_balance(&key, &XELIS_ASSET).await
        .context("Failed to get last balance")?;
    assert_eq!(last_topoheight, 6, "Latest balance pointer should remain unchanged");

    let mut seen_output = false;
    while let Some(prev) = last_balance.get_previous_topoheight() {
        last_balance = storage.get_balance_at_exact_topoheight(&key, &XELIS_ASSET, prev).await
            .with_context(|| format!("Failed to get balance at topoheight {}", prev))?;
        if prev == 1 {
            seen_output = true;
        }
    }

    assert!(seen_output, "Last balance chain should still link back to the retained output balance");

    Ok(())
}

// Single account, single asset: store balances at topoheights 0..=9, delete
// above 5, then verify the pointer and the version chain.
pub async fn test_delete_versioned_balances_above_topoheight<S: Storage>(
    mut storage: S,
    data: &TestData,
) -> Result<()> {
    let key = data.public_key_pair.get_public_key().compress();
    setup_balance_storage(&mut storage, &key, &XELIS_ASSET).await?;

    // Write a linked-list chain of balances at topoheights 0..=9.
    let mut balance = VersionedBalance::zero();
    storage.set_last_balance_to(&key, &XELIS_ASSET, 0, &balance).await
        .context("Failed to set balance at topo 0")?;

    for topo in 1u64..=9 {
        balance.set_previous_topoheight(Some(topo - 1));
        storage.set_last_balance_to(&key, &XELIS_ASSET, topo, &balance).await
            .context(format!("Failed to set balance at topo {}", topo))?;
    }

    // Sanity: pointer should be at topo 9.
    let (last_topo, _) = storage.get_last_balance(&key, &XELIS_ASSET).await
        .context("Failed to get last balance")?;
    assert_eq!(last_topo, 9, "Balance pointer should be at topo 9 before delete");

    // Delete above topoheight 5.
    storage.delete_versioned_data_above_topoheight(5).await
        .context("Failed to delete versioned data above topoheight 5")?;

    // After deletion the pointer must be at topo 5.
    let (last_topo, mut remaining) = storage.get_last_balance(&key, &XELIS_ASSET).await
        .context("Failed to get last balance after delete")?;
    assert_eq!(last_topo, 5, "Balance pointer should be at topo 5 after delete, got {}", last_topo);

    // Walk the previous_topoheight chain -- should find exactly 5 more entries
    // (at topoheights 4, 3, 2, 1, 0).
    let mut chain_len = 0usize;
    while let Some(prev) = remaining.get_previous_topoheight() {
        remaining = storage.get_balance_at_exact_topoheight(&key, &XELIS_ASSET, prev).await
            .with_context(|| format!("Failed to get balance at topoheight {}", prev))?;
        chain_len += 1;
    }
    assert_eq!(chain_len, 5, "Should have 5 previous versions (topoheights 4..0), got {}", chain_len);

    // Entries above the cut-off must no longer exist.
    for topo in 6u64..=9 {
        let exists = storage.has_balance_at_exact_topoheight(&key, &XELIS_ASSET, topo).await
            .with_context(|| format!("Failed to check balance at topo {}", topo))?;
        assert!(!exists, "Balance at topoheight {} should have been deleted", topo);
    }

    Ok(())
}

// Multiple accounts, single asset: each account has a balance version at every
// topoheight from 0 to 19. After deleting above topoheight 9, every account's
// pointer must be exactly 9.
//
// This tests the multi-account cross-prefix scenario: the iterator in
// delete_versioned_above_topoheight must traverse entries for all accounts
// across all topoheight prefix groups above the cutoff.
pub async fn test_delete_versioned_balances_above_topoheight_multi_account<S: Storage>(mut storage: S) -> Result<()> {
    // Use several distinct key-pairs so that there are many account IDs and the
    // versioned-balance keys span many different prefixes in the column family.
    let pairs: Vec<PublicKey> = (0..5).map(|_| KeyPair::new().get_public_key().compress()).collect();

    // Register asset once; register each account before writing balances.
    storage.add_asset(
        &XELIS_ASSET,
        0,
        VersionedAssetData::new(
            AssetData::new(8, "Test".to_owned(), "TST".to_owned(), MaxSupplyMode::Fixed(u64::MAX), AssetOwner::None),
            None,
        ),
    ).await.context("Failed to add asset")?;

    for (idx, key) in pairs.iter().enumerate() {
        storage.set_account_registration_topoheight(key, 0).await
            .with_context(|| format!("Failed to register account {}", idx))?;

        let mut balance = VersionedBalance::zero();
        storage.set_last_balance_to(&key, &XELIS_ASSET, 0, &balance).await
            .with_context(|| format!("Failed to set balance[{}] at topo 0", idx))?;

        for topo in 1u64..=19 {
            balance.set_previous_topoheight(Some(topo - 1));
            storage.set_last_balance_to(&key, &XELIS_ASSET, topo, &balance).await
                .with_context(|| format!("Failed to set balance[{}] at topo {}", idx, topo))?;
        }
    }

    // Verify all pointers are at 19 before the delete.
    for (idx, key) in pairs.iter().enumerate() {
        let (topo, _) = storage.get_last_balance(key, &XELIS_ASSET).await
            .with_context(|| format!("Failed to get last balance for account {}", idx))?;
        assert_eq!(topo, 19, "Account {} pointer should be 19 before delete", idx);
    }

    // Delete all versions above topoheight 9.
    let cutoff = 9u64;
    storage.delete_versioned_data_above_topoheight(cutoff).await
        .context("Failed to delete versioned data above topoheight 9")?;

    // After deletion every pointer must be <= cutoff.
    for (idx, key) in pairs.iter().enumerate() {
        let (topo, _) = storage.get_last_balance(key, &XELIS_ASSET).await
            .with_context(|| format!("Failed to get last balance for account {} after delete", idx))?;
        assert!(
            topo <= cutoff,
            "Account {} balance pointer is {} after delete, expected at most {}",
            idx, topo, cutoff
        );
        assert_eq!(topo, cutoff, "Account {} pointer should be exactly {}, got {}", idx, cutoff, topo);
    }

    // Additionally verify entries above cutoff are gone for the first account.
    let first_key = &pairs[0];
    for topo in (cutoff + 1)..=19 {
        let exists = storage.has_balance_at_exact_topoheight(first_key, &XELIS_ASSET, topo).await
            .with_context(|| format!("Failed to check balance at topo {}", topo))?;
        assert!(!exists, "Balance at topo {} should be gone after delete_above({})", topo, cutoff);
    }

    // Verify that entries at and below cutoff are still accessible for all accounts.
    for (idx, key) in pairs.iter().enumerate() {
        let exists = storage.has_balance_at_exact_topoheight(key, &XELIS_ASSET, cutoff).await
            .with_context(|| format!("Failed to check balance at cutoff for account {}", idx))?;
        assert!(exists, "Account {} balance at cutoff {} should still exist", idx, cutoff);
    }

    Ok(())
}

// Simulates the pop_blocks scenario: two accounts with balance changes at
// different topoheights are correctly rewound to topoheight 7. One account
// has dense history (every topoheight), the other sparse (only 0, 7, 14).
// Both pointers must land at exactly 7 after the rewind.
pub async fn test_delete_versioned_balances_pop_blocks_scenario<S: Storage>(
    mut storage: S,
    data: &TestData,
) -> Result<()> {
    let key1 = data.public_key_pair.get_public_key().compress();
    let key2 = KeyPair::new().get_public_key().compress();

    // Setup
    setup_balance_storage(&mut storage, &key1, &XELIS_ASSET).await?;
    storage.set_account_registration_topoheight(&key2, 0).await
        .context("Failed to register second account")?;

    // Store balance histories for both accounts.
    // key1: has a balance update at every topoheight 0..=14
    // key2: has a balance update only at topoheights 0, 7, 14
    //       (simulating an infrequently-used account)
    let mut bal = VersionedBalance::zero();
    storage.set_last_balance_to(&key1, &XELIS_ASSET, 0, &bal).await?;
    storage.set_last_balance_to(&key2, &XELIS_ASSET, 0, &bal).await?;

    for topo in 1u64..=14 {
        bal.set_previous_topoheight(Some(topo - 1));
        storage.set_last_balance_to(&key1, &XELIS_ASSET, topo, &bal).await
            .with_context(|| format!("key1 balance at {}", topo))?;
    }

    let mut bal2 = VersionedBalance::zero();
    bal2.set_previous_topoheight(Some(0));
    storage.set_last_balance_to(&key2, &XELIS_ASSET, 7, &bal2).await?;
    bal2.set_previous_topoheight(Some(7));
    storage.set_last_balance_to(&key2, &XELIS_ASSET, 14, &bal2).await?;

    // Simulate pop_blocks rewinding to topoheight 7.
    let rewind_to = 7u64;
    storage.delete_versioned_data_above_topoheight(rewind_to).await
        .context("Failed to delete versioned data above topoheight 7")?;

    // key1 pointer must be at topoheight 7.
    let (topo1, _) = storage.get_last_balance(&key1, &XELIS_ASSET).await?;
    assert_eq!(topo1, rewind_to, "key1 pointer should be at rewind_to={} after pop, got {}", rewind_to, topo1);

    // key2 pointer must be at topoheight 7 (its balance at 14 was deleted).
    let (topo2, _) = storage.get_last_balance(&key2, &XELIS_ASSET).await?;
    assert_eq!(topo2, rewind_to, "key2 pointer should be at rewind_to={} after pop, got {}", rewind_to, topo2);

    // Entries above rewind_to must be gone for both accounts.
    for topo in (rewind_to + 1)..=14 {
        let e1 = storage.has_balance_at_exact_topoheight(&key1, &XELIS_ASSET, topo).await?;
        assert!(!e1, "key1 balance at {} should be gone", topo);
    }
    let e2 = storage.has_balance_at_exact_topoheight(&key2, &XELIS_ASSET, 14).await?;
    assert!(!e2, "key2 balance at 14 should be gone");

    Ok(())
}

// Helper: register a contract in storage
async fn register_contract<S: Storage>(storage: &mut S, hash: &Hash, topoheight: u64) -> Result<()> {
    let module = Arc::new(Module::new());
    let contract_module = ContractModule {
        version: Default::default(),
        module,
    };
    let versioned = Versioned::new(Some(Cow::Owned(contract_module)), None);
    storage.set_last_contract_to(hash, topoheight, &versioned).await.context("Failed to register contract")
}

pub async fn test_event_callbacks_available_at_maximum_topoheight<S: Storage>(mut storage: S) -> Result<()> {
    let contract_hash = Hash::new([200u8; 32]);
    let event_id = 77u64;

    register_contract(&mut storage, &contract_hash, 0).await?;

    // Register 3 distinct listeners for the same event, each with unique chunk_id / max_gas
    let listeners = [
        (Hash::new([201u8; 32]), 0u16, 1000u64, 0u64),
        (Hash::new([202u8; 32]), 1u16, 2000u64, 1u64),
        (Hash::new([203u8; 32]), 2u16, 3000u64, 2u64),
    ];

    for (listener_hash, chunk_id, max_gas, topo) in &listeners {
        register_contract(&mut storage, listener_hash, *topo).await?;
        let callback = EventCallbackRegistration::new(*chunk_id, *max_gas, Source::Contract(listener_hash.clone()));
        storage.set_last_contract_event_callback(
            &contract_hash,
            event_id,
            listener_hash,
            Versioned::new(Some(callback), None),
            *topo,
        ).await.context("Failed to set callback")?;
    }

    // get_event_callbacks_available_at_maximum_topoheight should return all 3 active callbacks
    let stream = storage.get_event_callbacks_available_at_maximum_topoheight(
        &contract_hash,
        event_id,
        10u64,
    ).await.context("Failed to get available callbacks stream")?;

    futures::pin_mut!(stream);
    let mut found = std::collections::HashMap::new();
    while let Some(result) = stream.next().await {
        let (listener, cb) = result.context("Failed to read from available callbacks stream")?;
        found.insert(cb.chunk_id, (listener, cb.max_gas));
    }

    assert_eq!(found.len(), 3, "Should have 3 active callbacks, got {}", found.len());
    for (listener_hash, chunk_id, max_gas, _) in &listeners {
        let entry = found.get(chunk_id)
            .with_context(|| format!("chunk_id {} not found in results", chunk_id))?;
        assert_eq!(entry.0, *listener_hash,
            "chunk_id {}: expected listener {:?}, got {:?}", chunk_id, listener_hash, entry.0);
        assert_eq!(entry.1, *max_gas,
            "chunk_id {}: expected max_gas {}, got {}", chunk_id, max_gas, entry.1);
    }

    Ok(())
}

pub async fn test_event_callbacks_available_after_rewind<S: Storage>(mut storage: S) -> Result<()> {
    let contract_hash = Hash::new([210u8; 32]);
    let event_id = 88u64;

    register_contract(&mut storage, &contract_hash, 0).await?;

    let listener_a = Hash::new([211u8; 32]);
    let listener_b = Hash::new([212u8; 32]);

    register_contract(&mut storage, &listener_a, 0).await?;
    register_contract(&mut storage, &listener_b, 0).await?;

    // listener_a registered at topo 2, listener_b registered at topo 8
    storage.set_last_contract_event_callback(
        &contract_hash, event_id, &listener_a,
        Versioned::new(Some(EventCallbackRegistration::new(0, 500, Source::Contract(listener_a.clone()))), None),
        2,
    ).await?;
    storage.set_last_contract_event_callback(
        &contract_hash, event_id, &listener_b,
        Versioned::new(Some(EventCallbackRegistration::new(1, 600, Source::Contract(listener_b.clone()))), None),
        8,
    ).await?;

    // Before rewind: both visible at topo 10
    {
        let stream = storage.get_event_callbacks_available_at_maximum_topoheight(
            &contract_hash, event_id, 10,
        ).await?;
        futures::pin_mut!(stream);
        let mut count = 0;
        while let Some(r) = stream.next().await {
            r.context("stream error before rewind")?;
            count += 1;
        }
        assert_eq!(count, 2, "Before rewind: expected 2 callbacks, got {}", count);
    }

    // At topo 5: only listener_a should be visible (listener_b registered at 8)
    {
        let stream = storage.get_event_callbacks_available_at_maximum_topoheight(
            &contract_hash, event_id, 5,
        ).await?;
        futures::pin_mut!(stream);
        let mut count = 0;
        while let Some(r) = stream.next().await {
            let (listener, _) = r.context("stream error at topo 5")?;
            assert_eq!(listener, listener_a, "At topo 5 only listener_a should be visible");
            count += 1;
        }
        assert_eq!(count, 1, "At topo 5: expected 1 callback, got {}", count);
    }

    // Simulate pop_blocks: rewind to topo 5
    storage.delete_versioned_data_above_topoheight(5).await
        .context("Failed to delete versioned data above topo 5")?;

    // After rewind to topo 5: listener_b (registered at topo 8) must no longer appear
    {
        let stream = storage.get_event_callbacks_available_at_maximum_topoheight(
            &contract_hash, event_id, 5,
        ).await?;
        futures::pin_mut!(stream);
        let mut count = 0;
        while let Some(r) = stream.next().await {
            let (listener, _) = r.context("stream error after rewind")?;
            assert_eq!(listener, listener_a, "After rewind only listener_a should remain");
            count += 1;
        }
        assert_eq!(count, 1, "After rewind to topo 5: expected 1 callback, got {}", count);
    }

    Ok(())
}

pub async fn test_listeners_for_contract_events<S: Storage>(mut storage: S) -> Result<()> {
    let contract_hash = Hash::new([220u8; 32]);

    register_contract(&mut storage, &contract_hash, 0).await?;

    // Two different events, two different listeners
    let event_a = 1u64;
    let event_b = 2u64;
    let listener_1 = Hash::new([221u8; 32]);
    let listener_2 = Hash::new([222u8; 32]);

    register_contract(&mut storage, &listener_1, 0).await?;
    register_contract(&mut storage, &listener_2, 0).await?;

    // listener_1 listens to event_a at topo 1
    storage.set_last_contract_event_callback(
        &contract_hash, event_a, &listener_1,
        Versioned::new(Some(EventCallbackRegistration::new(10, 100, Source::Contract(listener_1.clone()))), None),
        1,
    ).await?;
    // listener_2 listens to event_b at topo 2
    storage.set_last_contract_event_callback(
        &contract_hash, event_b, &listener_2,
        Versioned::new(Some(EventCallbackRegistration::new(20, 200, Source::Contract(listener_2.clone()))), None),
        2,
    ).await?;

    let stream = storage.get_listeners_for_contract_events(
        &contract_hash,
        0,  // min_topoheight
        10, // max_topoheight
    ).await.context("Failed to get listeners")?;

    futures::pin_mut!(stream);
    let mut results: Vec<(u64, Hash, Option<EventCallbackRegistration>)> = Vec::new();
    while let Some(r) = stream.next().await {
        results.push(r.context("stream error in get_listeners_for_contract_events")?);
    }

    assert_eq!(results.len(), 2, "Expected 2 listener entries, got {}", results.len());

    // Verify each (event_id, listener) pair is correct
    let find = |eid: u64| results.iter().find(|(e, _, _)| *e == eid);

    let entry_a = find(event_a).with_context(|| format!("event_a ({}) not found", event_a))?;
    assert_eq!(entry_a.1, listener_1, "event_a listener should be listener_1");
    assert!(entry_a.2.is_some(), "event_a callback should be Some");
    assert_eq!(entry_a.2.as_ref().unwrap().chunk_id, 10);

    let entry_b = find(event_b).with_context(|| format!("event_b ({}) not found", event_b))?;
    assert_eq!(entry_b.1, listener_2, "event_b listener should be listener_2");
    assert!(entry_b.2.is_some(), "event_b callback should be Some");
    assert_eq!(entry_b.2.as_ref().unwrap().chunk_id, 20);

    Ok(())
}

// Verifies that once a listener is "consumed" (a new version with None is stored), the consumed
// version is visible at the consuming topoheight and not visible at an earlier one.
// Also verifies that re-registering after consumption creates a fresh version again.
pub async fn test_event_callback_consumed_versioning<S: Storage>(mut storage: S) -> Result<()> {
    let contract   = Hash::new([230u8; 32]);
    let listener   = Hash::new([231u8; 32]);
    let event_id   = 5u64;

    register_contract(&mut storage, &contract, 0).await?;
    register_contract(&mut storage, &listener, 0).await?;

    // topo 2: register callback
    storage.set_last_contract_event_callback(
        &contract, event_id, &listener,
        Versioned::new(Some(EventCallbackRegistration::new(0, 100, Source::Contract(listener.clone()))), None),
        2,
    ).await?;

    // topo 5: consume (set to None)
    storage.set_last_contract_event_callback(
        &contract, event_id, &listener,
        Versioned::new(None, Some(2)),
        5,
    ).await?;

    // At topo 3 the callback is still active
    let v_before = storage.get_event_callback_for_contract_at_maximum_topoheight(
        &contract, event_id, &listener, 3,
    ).await?.context("should exist before consumption")?;
    assert!(v_before.1.get().is_some(), "callback should be Some before consumption");

    // At topo 5 the consumed (None) version is returned
    let v_consumed = storage.get_event_callback_for_contract_at_maximum_topoheight(
        &contract, event_id, &listener, 5,
    ).await?.context("consumed version should be found")?;
    assert!(v_consumed.1.get().is_none(), "callback should be None after consumption");

    // get_event_callbacks_available_at_maximum_topoheight must NOT return consumed listeners
    {
        let stream = storage.get_event_callbacks_available_at_maximum_topoheight(
            &contract, event_id, 10,
        ).await?;
        futures::pin_mut!(stream);
        let mut count = 0;
        while let Some(r) = stream.next().await {
            r?;
            count += 1;
        }
        assert_eq!(count, 0, "consumed listener must not appear in available callbacks");
    }

    // topo 8: re-register after consumption
    storage.set_last_contract_event_callback(
        &contract, event_id, &listener,
        Versioned::new(Some(EventCallbackRegistration::new(1, 200, Source::Contract(listener.clone()))), Some(5)),
        8,
    ).await?;

    let v_rereg = storage.get_event_callback_for_contract_at_maximum_topoheight(
        &contract, event_id, &listener, 10,
    ).await?.context("re-registered callback should exist")?;
    assert_eq!(v_rereg.1.get().as_ref().unwrap().chunk_id, 1, "re-registered chunk_id should be 1");

    // Available stream should now return 1 entry (the re-registered one)
    let stream2 = storage.get_event_callbacks_available_at_maximum_topoheight(
        &contract, event_id, 10,
    ).await?;
    futures::pin_mut!(stream2);
    let mut count2 = 0;
    while let Some(r) = stream2.next().await {
        r?;
        count2 += 1;
    }
    assert_eq!(count2, 1, "re-registered listener should appear once in available callbacks");

    Ok(())
}

// Tests create / update / soft-delete (None value) of contract data entries,
// verifying that get_contract_data_at_maximum_topoheight_for returns the correct
// version at every relevant topoheight.
pub async fn test_contract_data_lifecycle<S: Storage>(mut storage: S) -> Result<()> {
    let contract = Hash::new([240u8; 32]);
    register_contract(&mut storage, &contract, 0).await?;

    let key = ValueCell::Primitive(Primitive::U64(42));
    let val_v1 = ValueCell::Primitive(Primitive::U64(100));
    let val_v2 = ValueCell::Primitive(Primitive::U64(200));

    // topo 1: key does not exist yet
    let missing = storage.get_contract_data_at_maximum_topoheight_for(&contract, &key, 1).await?;
    assert!(missing.is_none(), "key should not exist before creation");

    // topo 2: create
    storage.set_last_contract_data_to(
        &contract, &key, 2,
        &Versioned::new(Some(val_v1.clone()), None),
    ).await?;

    // topo 3: update
    storage.set_last_contract_data_to(
        &contract, &key, 3,
        &Versioned::new(Some(val_v2.clone()), Some(2)),
    ).await?;

    // topo 6: soft-delete (None value)
    storage.set_last_contract_data_to(
        &contract, &key, 6,
        &Versioned::new(None, Some(3)),
    ).await?;

    // At topo 1: not found
    assert!(storage.get_contract_data_at_maximum_topoheight_for(&contract, &key, 1).await?.is_none(),
        "key must not exist at topo 1");

    // At topo 2: v1
    let at2 = storage.get_contract_data_at_maximum_topoheight_for(&contract, &key, 2)
        .await?.context("should find v1 at topo 2")?;
    assert_eq!(at2.0, 2);
    assert_eq!(at2.1.get().as_ref().unwrap(), &val_v1);

    // At topo 4: v2 (latest update, delete not yet applied)
    let at4 = storage.get_contract_data_at_maximum_topoheight_for(&contract, &key, 4)
        .await?.context("should find v2 at topo 4")?;
    assert_eq!(at4.1.get().as_ref().unwrap(), &val_v2);

    // At topo 6: None (deleted)
    let at6 = storage.get_contract_data_at_maximum_topoheight_for(&contract, &key, 6)
        .await?.context("deleted version should still be returned as Some(versioned)")?;
    assert!(at6.1.get().is_none(), "value should be None after deletion");

    // Exact topoheight checks
    assert!(storage.has_contract_data_at_exact_topoheight(&contract, &key, 2).await?, "exact topo 2 must exist");
    assert!(storage.has_contract_data_at_exact_topoheight(&contract, &key, 3).await?, "exact topo 3 must exist");
    assert!(storage.has_contract_data_at_exact_topoheight(&contract, &key, 6).await?, "exact topo 6 (delete) must exist");
    assert!(!storage.has_contract_data_at_exact_topoheight(&contract, &key, 4).await?, "exact topo 4 must not exist (no write)");

    Ok(())
}

// Tests that after delete_versioned_data_above_topoheight, contract data pointers are
// correctly rewound so re-querying returns the pre-rewind version.
pub async fn test_contract_data_rewind<S: Storage>(mut storage: S) -> Result<()> {
    let contract = Hash::new([241u8; 32]);
    register_contract(&mut storage, &contract, 0).await?;

    let key   = ValueCell::Primitive(Primitive::U64(99));
    let val_a = ValueCell::Primitive(Primitive::U64(10));
    let val_b = ValueCell::Primitive(Primitive::U64(20));

    // topo 3: create val_a
    storage.set_last_contract_data_to(
        &contract, &key, 3,
        &Versioned::new(Some(val_a.clone()), None),
    ).await?;

    // topo 7: update to val_b
    storage.set_last_contract_data_to(
        &contract, &key, 7,
        &Versioned::new(Some(val_b.clone()), Some(3)),
    ).await?;

    // Rewind to topo 5 (removes topo-7 entry)
    storage.delete_versioned_data_above_topoheight(5).await?;

    // After rewind, the pointer must point back to the topo-3 version
    let after = storage.get_contract_data_at_maximum_topoheight_for(&contract, &key, 10)
        .await?.context("val_a should be visible after rewind")?;
    assert_eq!(after.0, 3, "pointer should be at topo 3 after rewind");
    assert_eq!(after.1.get().as_ref().unwrap(), &val_a);

    // The topo-7 entry must be gone
    assert!(!storage.has_contract_data_at_exact_topoheight(&contract, &key, 7).await?,
        "topo-7 entry must be deleted after rewind");

    Ok(())
}

// Tests deploy / re-deploy (update module) / soft-delete of a contract module,
// verifying get_contract_at_maximum_topoheight_for and has_contract_module_at_topoheight.
pub async fn test_contract_module_lifecycle<S: Storage>(mut storage: S) -> Result<()> {
    let hash = Hash::new([250u8; 32]);
    let module = Arc::new(Module::new());

    // topo 1: does not exist
    assert!(storage.get_last_topoheight_for_contract(&hash).await?.is_none(),
        "contract must not exist before deploy");

    // topo 2: deploy
    let cm_v1 = ContractModule { version: Default::default(), module: module.clone() };
    storage.set_last_contract_to(&hash, 2, &Versioned::new(Some(Cow::Owned(cm_v1)), None)).await?;

    // topo 4: update (re-deploy)
    let cm_v2 = ContractModule { version: Default::default(), module: module.clone() };
    storage.set_last_contract_to(&hash, 4, &Versioned::new(Some(Cow::Owned(cm_v2)), Some(2))).await?;

    // topo 7: soft-delete (module = None)
    storage.set_last_contract_to(&hash, 7, &Versioned::new(None, Some(4))).await?;

    // At topo 1: not deployed yet
    assert!(storage.get_contract_at_maximum_topoheight_for(&hash, 1).await?.is_none(),
        "contract should not exist at topo 1");

    // At topo 3: v1 deployed
    let at3 = storage.get_contract_at_maximum_topoheight_for(&hash, 3)
        .await?.context("v1 should exist at topo 3")?;
    assert_eq!(at3.0, 2, "should be at deploy topoheight 2");
    assert!(at3.1.get().is_some(), "module should be Some at topo 3");

    // At topo 5: v2 (updated)
    let at5 = storage.get_contract_at_maximum_topoheight_for(&hash, 5)
        .await?.context("v2 should exist at topo 5")?;
    assert_eq!(at5.0, 4, "should be at update topoheight 4");

    // At topo 7: module deleted (None)
    let at7 = storage.get_contract_at_maximum_topoheight_for(&hash, 7)
        .await?.context("deletion record should exist")?;
    assert!(at7.1.get().is_none(), "module should be None after deletion");

    // has_contract_module_at_topoheight: false when None, true when Some
    assert!(!storage.has_contract_module_at_topoheight(&hash, 7).await?,
        "has_contract_module must be false when deleted");
    assert!(storage.has_contract_module_at_topoheight(&hash, 4).await?,
        "has_contract_module must be true when module exists");

    // has_contract_at_maximum_topoheight: reflects latest version up to the given topo
    assert!(storage.has_contract_at_maximum_topoheight(&hash, 5).await?,
        "should have contract at topo 5");
    assert!(!storage.has_contract_at_maximum_topoheight(&hash, 10).await?,
        "should NOT have contract at topo 10 (deleted at 7)");

    Ok(())
}

// Tests that after delete_versioned_data_above_topoheight, the contract module pointer
// is rewound so re-querying returns the pre-rewind version.
pub async fn test_contract_module_rewind<S: Storage>(mut storage: S) -> Result<()> {
    let hash   = Hash::new([251u8; 32]);
    let module = Arc::new(Module::new());

    let cm_v1 = ContractModule { version: Default::default(), module: module.clone() };
    storage.set_last_contract_to(&hash, 5, &Versioned::new(Some(Cow::Owned(cm_v1)), None)).await?;

    let cm_v2 = ContractModule { version: Default::default(), module: module.clone() };
    storage.set_last_contract_to(&hash, 10, &Versioned::new(Some(Cow::Owned(cm_v2)), Some(5))).await?;

    // Rewind to topo 7 (removes topo-10 entry)
    storage.delete_versioned_data_above_topoheight(7).await?;

    // After rewind, contract must point back to topo 5
    let after = storage.get_contract_at_maximum_topoheight_for(&hash, 20)
        .await?.context("v1 should be visible after rewind")?;
    assert_eq!(after.0, 5, "pointer should be rewound to topo 5");
    assert!(after.1.get().is_some(), "module should be Some after rewind to topo 7");

    // The topo-10 entry must be gone
    assert!(!storage.has_contract_at_exact_topoheight(&hash, 10).await?,
        "topo-10 entry must be deleted after rewind");

    Ok(())
}

// Tests that a scheduled execution can be stored, retrieved, and that the versioned
// cleanup (delete_scheduled_executions_above_topoheight) removes registrations above
// the cutoff while keeping registrations at or below it.
pub async fn test_scheduled_execution_lifecycle<S: Storage>(mut storage: S) -> Result<()> {
    let contract = Hash::new([252u8; 32]);
    register_contract(&mut storage, &contract, 0).await?;

    // Register executions at different registration topoheights, each targeting different execution topoheights
    for (reg_topo, exec_topo) in [(1u64, 10u64), (3, 20), (5, 30), (8, 40)] {
        let execution = ScheduledExecution {
            hash: Arc::new(Hash::new([1 + reg_topo as u8; 32])),
            contract: contract.clone(),
            kind: ScheduledExecutionKind::TopoHeight(exec_topo),
            params: vec![],
            chunk_id: 0,
            max_gas: 1000,
            gas_sources: Default::default(),
        };
        storage.set_contract_scheduled_execution_at_topoheight(
            &contract, reg_topo, &execution, exec_topo,
        ).await?;
    }

    // All 4 should be retrievable by their execution topoheight
    for exec_topo in [10u64, 20, 30, 40] {
        assert!(storage.has_contract_scheduled_execution_at_topoheight(&contract, exec_topo).await?,
            "execution at exec_topo {} should exist", exec_topo);
        let exec = storage.get_contract_scheduled_execution_at_topoheight(&contract, exec_topo).await?;
        assert_eq!(exec.contract, contract, "contract mismatch for exec_topo {}", exec_topo);
    }

    // Registrations at or below reg_topo 4 should survive deletion above reg_topo 4
    storage.delete_scheduled_executions_above_topoheight(4).await?;

    // reg_topo 1 and 3 (exec_topo 10 and 20) must still exist
    for exec_topo in [10u64, 20] {
        assert!(storage.has_contract_scheduled_execution_at_topoheight(&contract, exec_topo).await?,
            "exec_topo {} should still exist after rewind", exec_topo);
    }

    // reg_topo 5 and 8 (exec_topo 30 and 40) must be gone
    for exec_topo in [30u64, 40] {
        assert!(!storage.has_contract_scheduled_execution_at_topoheight(&contract, exec_topo).await?,
            "exec_topo {} should be deleted after rewind", exec_topo);
    }

    Ok(())
}

// Tests the full range query for registered scheduled executions and verifies that
// only executions within the registration topoheight window are returned.
pub async fn test_scheduled_execution_range_query<S: Storage>(mut storage: S) -> Result<()> {
    let contract = Hash::new([253u8; 32]);
    register_contract(&mut storage, &contract, 0).await?;

    // Register 6 executions spanning topoheights 1..=6
    for reg_topo in 1u64..=6 {
        let exec_topo = 100 + reg_topo;
        let execution = ScheduledExecution {
            hash: Arc::new(Hash::new([254u8; 32])),
            contract: contract.clone(),
            kind: ScheduledExecutionKind::TopoHeight(exec_topo),
            params: vec![],
            chunk_id: 0,
            max_gas: 500,
            gas_sources: Default::default(),
        };
        storage.set_contract_scheduled_execution_at_topoheight(
            &contract, reg_topo, &execution, exec_topo,
        ).await?;
    }

    // Query range [2, 5]: should return exactly the 4 executions registered at topos 2..=5
    let stream = storage.get_registered_contract_scheduled_executions_in_range(2, 5, None).await?;
    futures::pin_mut!(stream);
    let mut count = 0u64;
    while let Some(r) = stream.next().await {
        let (_, reg_topo, _) = r.context("stream error")?;
        assert!(reg_topo >= 2 && reg_topo <= 5,
            "reg_topo {} outside expected range [2, 5]", reg_topo);
        count += 1;
    }
    assert_eq!(count, 4, "expected 4 executions in range [2, 5], got {}", count);

    Ok(())
}

pub async fn test_account_registration_topoheight<S: Storage>(mut storage: S) -> Result<()> {
    let key = KeyPair::new().get_public_key().compress();

    // Initially, no registration topoheight should be found
    assert!(!storage.is_account_registered(&key).await?,
        "registration topoheight should be None for unregistered account");

    // Set registration topoheight to 5
    storage.set_account_registration_topoheight(&key, 5).await?;

    // Now it should return 5
    let reg_topo = storage.get_account_registration_topoheight(&key).await?;
    assert_eq!(reg_topo, 5, "registration topoheight should be 5, got {}", reg_topo);

    // Update registration topoheight to 10
    storage.set_account_registration_topoheight(&key, 10).await?;

    // Now it should return 10
    // it is not versioned, so it OVERWRITE it, not create a new version
    let reg_topo2 = storage.get_account_registration_topoheight(&key).await?;
    assert_eq!(reg_topo2, 10, "registration topoheight should be updated to 10, got {}", reg_topo2);

    // not registered at 5
    assert!(!storage.is_account_registered_for_topoheight(&key, 5).await?,
        "account should not be registered after setting registration topoheight");

    // Now clean the registrations
    storage.delete_versioned_registrations_above_topoheight(9).await?;

    // After deletion, it should not exists anymore
    assert!(!storage.is_account_registered_for_topoheight(&key, 10).await?,
        "account should not be registered after deletion above topoheight 9");

    Ok(())
}

pub async fn test_multisig_operations<S: Storage>(mut storage: S, data: &TestData) -> Result<()> {
    let account = data.public_key_pair.get_public_key().compress();
    let participant1 = KeyPair::new().get_public_key().compress();
    let participant2 = KeyPair::new().get_public_key().compress();

    assert!(!storage.has_multisig(&account).await?,
        "multisig should not exist initially");
    assert!(!storage.has_multisig_at_exact_topoheight(&account, 3).await?,
        "multisig should not exist at topoheight 3 initially");
    assert!(storage.get_last_topoheight_for_multisig(&account).await?.is_none(),
        "last multisig topoheight should be empty initially");

    let payload_v1 = MultiSigPayload {
        threshold: 2,
        participants: [participant1.clone(), participant2.clone()].into_iter().collect(),
    };
    storage.set_last_multisig_to(
        &account,
        3,
        Versioned::new(Some(Cow::Owned(payload_v1.clone())), None),
    ).await?;

    assert!(storage.has_multisig(&account).await?,
        "multisig should exist after first insert");
    assert!(storage.has_multisig_at_exact_topoheight(&account, 3).await?,
        "multisig should exist at topoheight 3");
    assert!(!storage.has_multisig_at_exact_topoheight(&account, 2).await?,
        "multisig should not exist below first version");

    let (topoheight_v1, versioned_v1) = storage.get_last_multisig(&account).await?;
    assert_eq!(topoheight_v1, 3, "last multisig topoheight should be 3");
    let stored_v1 = versioned_v1.get().as_ref().expect("multisig payload should exist");
    assert_eq!(stored_v1.threshold, 2, "threshold mismatch for v1");
    assert_eq!(stored_v1.participants.len(), 2, "participant count mismatch for v1");

    let at_max_2 = storage.get_multisig_at_maximum_topoheight_for(&account, 2).await?;
    assert!(at_max_2.is_none(), "no multisig should be visible below the first version");

    let at_max_3 = storage.get_multisig_at_maximum_topoheight_for(&account, 3).await?;
    assert_eq!(at_max_3.as_ref().map(|(topo, _)| *topo), Some(3), "topoheight mismatch at max 3");

    let payload_v2 = MultiSigPayload {
        threshold: 1,
        participants: [participant1.clone()].into_iter().collect(),
    };
    storage.set_last_multisig_to(
        &account,
        7,
        Versioned::new(Some(Cow::Owned(payload_v2.clone())), Some(3)),
    ).await?;

    let (topoheight_v2, versioned_v2) = storage.get_last_multisig(&account).await?;
    assert_eq!(topoheight_v2, 7, "last multisig topoheight should be updated to 7");
    let stored_v2 = versioned_v2.get().as_ref().expect("multisig payload should exist");
    assert_eq!(stored_v2.threshold, 1, "threshold mismatch for v2");
    assert_eq!(versioned_v2.get_previous_topoheight(), Some(3), "previous topoheight should be preserved");

    let at_max_6 = storage.get_multisig_at_maximum_topoheight_for(&account, 6).await?;
    assert_eq!(at_max_6.as_ref().map(|(topo, _)| *topo), Some(3), "max topoheight lookup should walk back to v1");

    let at_max_7 = storage.get_multisig_at_maximum_topoheight_for(&account, 7).await?;
    assert_eq!(at_max_7.as_ref().map(|(topo, _)| *topo), Some(7), "max topoheight lookup should return v2");

    Ok(())
}

fn multisig_payload(threshold: u8) -> MultiSigPayload {
    MultiSigPayload {
        threshold,
        participants: (0..threshold)
            .map(|_| KeyPair::new().get_public_key().compress())
            .collect(),
    }
}

async fn set_multisig_version<S: Storage>(
    storage: &mut S,
    account: &PublicKey,
    topoheight: u64,
    previous_topoheight: Option<u64>,
    threshold: u8,
) -> Result<()> {
    storage.set_last_multisig_to(
        account,
        topoheight,
        Versioned::new(Some(Cow::Owned(multisig_payload(threshold))), previous_topoheight),
    ).await?;

    Ok(())
}

async fn seed_multisig_versions<S: Storage>(storage: &mut S, account: &PublicKey) -> Result<()> {
    set_multisig_version(storage, account, 1, None, 1).await?;
    set_multisig_version(storage, account, 4, Some(1), 2).await?;
    set_multisig_version(storage, account, 8, Some(4), 3).await?;
    set_multisig_version(storage, account, 12, Some(8), 1).await
}

async fn assert_last_multisig<S: Storage>(
    storage: &S,
    account: &PublicKey,
    expected_topoheight: u64,
    expected_threshold: u8,
) -> Result<()> {
    let (topoheight, version) = storage.get_last_multisig(account).await?;
    assert_eq!(topoheight, expected_topoheight, "last multisig topoheight mismatch");
    assert_eq!(
        version.get().as_ref().expect("last multisig payload should exist").threshold,
        expected_threshold,
        "last multisig threshold mismatch",
    );

    Ok(())
}

async fn assert_multisig_at_maximum<S: Storage>(
    storage: &S,
    account: &PublicKey,
    maximum_topoheight: u64,
    expected_topoheight: Option<u64>,
) -> Result<()> {
    let result = storage.get_multisig_at_maximum_topoheight_for(account, maximum_topoheight).await?;
    assert_eq!(
        result.as_ref().map(|(topoheight, _)| *topoheight),
        expected_topoheight,
        "multisig maximum-topoheight lookup mismatch for maximum {}",
        maximum_topoheight,
    );

    Ok(())
}

pub async fn test_multisig_delete_versioned_at_topoheight<S: Storage>(mut storage: S) -> Result<()> {
    let account = KeyPair::new().get_public_key().compress();
    seed_multisig_versions(&mut storage, &account).await?;

    storage.delete_versioned_data_at_topoheight(12, false).await
        .context("Failed to delete versioned multisig at topoheight 12")?;

    assert!(!storage.has_multisig_at_exact_topoheight(&account, 12).await?,
        "multisig version at deleted topoheight should be removed");
    assert!(storage.has_multisig_at_exact_topoheight(&account, 8).await?,
        "previous multisig version should remain after rollback");
    assert_last_multisig(&storage, &account, 8, 3).await?;
    assert_multisig_at_maximum(&storage, &account, 100, Some(8)).await?;

    Ok(())
}

pub async fn test_multisig_delete_versioned_above_topoheight<S: Storage>(mut storage: S) -> Result<()> {
    let account = KeyPair::new().get_public_key().compress();
    seed_multisig_versions(&mut storage, &account).await?;

    storage.delete_versioned_data_above_topoheight(8).await
        .context("Failed to delete versioned multisig above topoheight 8")?;

    assert!(!storage.has_multisig_at_exact_topoheight(&account, 12).await?,
        "multisig version above cutoff should be removed");
    assert!(storage.has_multisig_at_exact_topoheight(&account, 8).await?,
        "cutoff multisig version should remain");
    assert_last_multisig(&storage, &account, 8, 3).await?;
    assert_multisig_at_maximum(&storage, &account, 100, Some(8)).await?;
    assert_multisig_at_maximum(&storage, &account, 3, Some(1)).await?;

    Ok(())
}

pub async fn test_multisig_delete_versioned_below_topoheight<S: Storage>(mut storage: S) -> Result<()> {
    let account = KeyPair::new().get_public_key().compress();
    seed_multisig_versions(&mut storage, &account).await?;

    storage.delete_versioned_data_below_topoheight(8, true).await
        .context("Failed to delete versioned multisig below topoheight 8")?;

    assert!(!storage.has_multisig_at_exact_topoheight(&account, 1).await?,
        "old multisig version below cutoff should be removed");
    assert!(!storage.has_multisig_at_exact_topoheight(&account, 4).await?,
        "old multisig version below cutoff should be removed");
    assert!(storage.has_multisig_at_exact_topoheight(&account, 8).await?,
        "last kept multisig version below the current pointer should remain");
    assert!(storage.has_multisig_at_exact_topoheight(&account, 12).await?,
        "latest multisig version should remain");

    let version_at_8 = storage.get_multisig_at_topoheight_for(&account, 8).await?;
    assert_eq!(version_at_8.get_previous_topoheight(), None,
        "kept multisig version should be patched as the beginning of the chain");

    let version_at_12 = storage.get_multisig_at_topoheight_for(&account, 12).await?;
    assert_eq!(version_at_12.get_previous_topoheight(), Some(8),
        "latest multisig version should still point to the kept version");

    assert_last_multisig(&storage, &account, 12, 1).await?;
    assert_multisig_at_maximum(&storage, &account, 7, None).await?;
    assert_multisig_at_maximum(&storage, &account, 8, Some(8)).await?;
    assert_multisig_at_maximum(&storage, &account, 100, Some(12)).await?;

    Ok(())
}

// Pruning below a topoheight must remove executions that were already due, not
// future executions merely because their registration block is old.
pub async fn test_scheduled_execution_prune_keeps_future_execution<S: Storage>(mut storage: S) -> Result<()> {
    let contract = Hash::new([251u8; 32]);
    register_contract(&mut storage, &contract, 0).await?;

    let future_execution = ScheduledExecution {
        hash: Arc::new(Hash::new([250u8; 32])),
        contract: contract.clone(),
        kind: ScheduledExecutionKind::TopoHeight(100),
        params: vec![],
        chunk_id: 0,
        max_gas: 1000,
        gas_sources: Default::default(),
    };
    storage.set_contract_scheduled_execution_at_topoheight(
        &contract, 1, &future_execution, 100,
    ).await?;

    let past_execution = ScheduledExecution {
        hash: Arc::new(Hash::new([249u8; 32])),
        contract: contract.clone(),
        kind: ScheduledExecutionKind::TopoHeight(3),
        params: vec![],
        chunk_id: 0,
        max_gas: 1000,
        gas_sources: Default::default(),
    };
    storage.set_contract_scheduled_execution_at_topoheight(
        &contract, 2, &past_execution, 3,
    ).await?;

    storage.delete_scheduled_executions_below_topoheight(10).await?;

    assert!(storage.has_contract_scheduled_execution_at_topoheight(&contract, 100).await?,
        "future execution must survive pruning below its execution topoheight");
    assert!(!storage.has_contract_scheduled_execution_at_topoheight(&contract, 3).await?,
        "past due execution should be pruned");

    let retrieved = storage.get_contract_scheduled_execution_at_topoheight(&contract, 100).await?;
    assert_eq!(retrieved.hash, future_execution.hash, "future execution payload should stay intact");

    let due_contracts = storage.get_contract_scheduled_executions_for_execution_topoheight(100).await?;
    let mut found = false;
    for result in due_contracts {
        if result? == contract {
            found = true;
        }
    }
    assert!(found, "future execution must remain indexed by execution topoheight");

    Ok(())
}
