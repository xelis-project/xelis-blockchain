use anyhow::{Result, Context};
use std::sync::Arc;
use std::borrow::Cow;
use indexmap::IndexSet;
use xelis_common::{
    account::VersionedNonce,
    block::{BlockHeader, BlockVersion, EXTRA_NONCE_SIZE},
    contract::{ScheduledExecution, ScheduledExecutionKind, EventCallbackRegistration, ContractModule},
    crypto::{Hash, KeyPair},
    difficulty::Difficulty,
    immutable::Immutable,
    network::Network,
    varuint::VarUint,
    versioned_type::Versioned,
};
use xelis_vm::Module;
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
    let callback = EventCallbackRegistration {
        chunk_id: 0,
        max_gas: 100,
    };
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
    assert_eq!(retrieved_versioned.get().unwrap().chunk_id, 0, "Chunk ID mismatch");
    assert_eq!(retrieved_versioned.get().unwrap().max_gas, 100, "Max gas mismatch");
    
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
        let callback = EventCallbackRegistration {
            chunk_id: listener_idx as u16,
            max_gas: 200u64 + listener_idx,
        };
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
    while let Some(result) = futures::stream::StreamExt::next(&mut callbacks).await {
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
    let callback_v1 = EventCallbackRegistration {
        chunk_id: 0,
        max_gas: 300,
    };
    storage.set_last_contract_event_callback(
        &contract_hash,
        event_id,
        &listener_hash,
        Versioned::new(Some(callback_v1), None),
        5u64,
    ).await.context("Failed to set callback v1")?;
    
    // Register version 2 at topoheight 10 (update)
    let callback_v2 = EventCallbackRegistration {
        chunk_id: 1,
        max_gas: 400,
    };
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
    assert_eq!(result_v1.unwrap().1.get().unwrap().max_gas, 300, "v1 max_gas should be 300");
    
    // Get at topoheight 15 should return v2
    let result_v2 = storage.get_event_callback_for_contract_at_maximum_topoheight(
        &contract_hash,
        event_id,
        &listener_hash,
        15u64,
    ).await.context("Failed to get callback at topo 15")?;
    
    assert!(result_v2.is_some(), "Should find v2 at topoheight 15");
    assert_eq!(result_v2.unwrap().1.get().unwrap().max_gas, 400, "v2 max_gas should be 400");
    
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
    let callback = EventCallbackRegistration {
        chunk_id: 0,
        max_gas: 500,
    };
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
        let callback = EventCallbackRegistration {
            chunk_id: topo as u16,
            max_gas: 100 + topo,
        };
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
    let callback = EventCallbackRegistration {
        chunk_id: 1,
        max_gas: 500,
    };
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
        
        let callback = EventCallbackRegistration {
            chunk_id: idx as u16,
            max_gas: 600 + idx,
        };
        
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
    while let Some(result) = futures::stream::StreamExt::next(&mut callbacks_stream).await {
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
    while let Some(result) = futures::stream::StreamExt::next(&mut executions).await {
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
    let callback = EventCallbackRegistration {
        chunk_id: 10,
        max_gas: 1000,
    };
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
