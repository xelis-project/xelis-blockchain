use curve25519_dalek::Scalar;
use indexmap::IndexMap;

use crate::{
    config::XELIS_ASSET,
    crypto::{
        Hash,
        proofs::G
    },
    transaction::{
        mock::{MockAccount, MockChainState},
        verify::{BlockchainApplyState, BlockchainContractState}
    },
    versioned::VersionedState
};

#[tokio::test]
async fn test_blockchain_apply_state_gas_tracking() {
    let mut state = MockChainState::new();
    
    // Test gas fee tracking
    state.add_gas_fee(1000).await.unwrap();
    assert_eq!(state.gas_fee, 1000);
    
    state.add_gas_fee(500).await.unwrap();
    assert_eq!(state.gas_fee, 1500);
    
    // Test burned fee tracking
    state.add_burned_fee(250).await.unwrap();
    assert_eq!(state.burned_fee, 250);
    
    // Test burned coins tracking
    state.add_burned_coins(&XELIS_ASSET, 100).await.unwrap();
    assert_eq!(state.burned_coins.get(&XELIS_ASSET), Some(&100));
    
    state.add_burned_coins(&XELIS_ASSET, 50).await.unwrap();
    assert_eq!(state.burned_coins.get(&XELIS_ASSET), Some(&150));
}

#[tokio::test]
async fn test_contract_balance_for_gas() {
    let mut state = MockChainState::new();
    let contract_hash = Hash::zero();
    
    // Get contract balance (should initialize to 0)
    {
        let (versioned_state, balance) = state.get_contract_balance_for_gas(&contract_hash).await.unwrap();
        assert_eq!(*balance, 0);
        assert_eq!(*versioned_state, VersionedState::New);
        
        // Update the balance
        *balance = 5000;
        // New state doesn't change when marked as updated
        versioned_state.mark_updated();
        assert_eq!(*versioned_state, VersionedState::New); // Still new
    }
    
    // Verify the update persisted in the state
    {
        let (versioned_state, balance) = state.get_contract_balance_for_gas(&contract_hash).await.unwrap();
        assert_eq!(*balance, 5000);
        // The state is still the same object, so it's still New
        assert_eq!(*versioned_state, VersionedState::New);
    }
    
    // Simulate fetching from storage
    {
        let cache = state.contract_caches.get_mut(&contract_hash).unwrap();
        let (versioned_state, _) = cache.balances.get_mut(&XELIS_ASSET)
            .unwrap()
            .as_mut()
            .unwrap();
        *versioned_state = VersionedState::FetchedAt(10);
    }
    
    // Now mark it as updated
    {
        let (versioned_state, balance) = state.get_contract_balance_for_gas(&contract_hash).await.unwrap();
        assert_eq!(*versioned_state, VersionedState::FetchedAt(10));
        *balance = 6000;
        versioned_state.mark_updated();
        assert_eq!(*versioned_state, VersionedState::Updated(10));
    }
}

#[tokio::test]
async fn test_refund_gas_sources_single_contract() {
    use crate::contract::{vm::refund_gas_sources, Source};

    let mut state = MockChainState::new();
    let contract_hash = Hash::zero();
    
    // Initialize contract with balance
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract_hash).await.unwrap();
        *balance = 1000;
    }
    
    // Create gas sources - contract injected 1000 gas
    let mut gas_sources = IndexMap::new();
    gas_sources.insert(Source::Contract(contract_hash.clone()), 1000);
    
    // Used gas: 600, max gas: 1000
    // Should refund: 1000 - 600 = 400
    refund_gas_sources(&mut state, gas_sources, 600, 1000).await.unwrap();
    
    // Check contract balance was refunded
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract_hash).await.unwrap();
        assert_eq!(*balance, 1400); // 1000 + 400 refund
    }
}

#[tokio::test]
async fn test_refund_gas_sources_single_account() {
    use crate::contract::{vm::refund_gas_sources, Source};
    use crate::crypto::KeyPair;

    let mut state = MockChainState::new();
    let keypair = KeyPair::new();
    let account = keypair.get_public_key().compress();
    
    // Initialize account with balance (encrypted)
    {
        let balance_ct = keypair.get_public_key().encrypt(2000u64);
        state.accounts.insert(account.clone(), MockAccount {
            balances: [(XELIS_ASSET, balance_ct)].into_iter().collect(),
            nonce: 0,
        });
    }
    
    // Create gas sources - account paid 500 gas
    let mut gas_sources = IndexMap::new();
    gas_sources.insert(Source::Account(account.clone()), 500);
    
    // Used gas: 300, max gas: 500
    // Should refund: 500 - 300 = 200
    refund_gas_sources(&mut state, gas_sources, 300, 500).await.unwrap();
    
    // Check account balance was refunded (should add 200 to the ciphertext)
    let balance_ct = &state.accounts.get(&account).unwrap().balances[&XELIS_ASSET];
    let decrypted = keypair.decrypt_to_point(balance_ct);
    assert_eq!(decrypted, Scalar::from(2200u64) * (*G)); // 2000 + 200 refund
}

#[tokio::test]
async fn test_refund_gas_sources_multiple_contracts() {
    use crate::contract::{vm::refund_gas_sources, Source};

    let mut state = MockChainState::new();
    let contract1 = Hash::zero();
    let contract2 = Hash::new([1u8; 32]);
    
    // Initialize contracts with balances
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract1).await.unwrap();
        *balance = 500;
    }
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract2).await.unwrap();
        *balance = 800;
    }
    
    // Create gas sources
    // contract1 injected 200 gas, contract2 injected 200 gas
    // Total: 400 gas
    let mut gas_sources = IndexMap::new();
    gas_sources.insert(Source::Contract(contract1.clone()), 200);
    gas_sources.insert(Source::Contract(contract2.clone()), 200);
    
    // Used gas: 300, max gas: 400
    // Should refund: 400 - 300 = 100
    // Each contract should get proportional refund: 50 each (100 * 200/400)
    refund_gas_sources(&mut state, gas_sources, 300, 400).await.unwrap();
    
    // Check balances
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract1).await.unwrap();
        assert_eq!(*balance, 550); // 500 + 50 refund
    }
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract2).await.unwrap();
        assert_eq!(*balance, 850); // 800 + 50 refund
    }
}

#[tokio::test]
async fn test_refund_gas_sources_proportional_different_amounts() {
    use crate::contract::{vm::refund_gas_sources, Source};

    let mut state = MockChainState::new();
    let contract1 = Hash::zero();
    let contract2 = Hash::new([1u8; 32]);
    
    // Initialize contracts with balances
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract1).await.unwrap();
        *balance = 1000;
    }
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract2).await.unwrap();
        *balance = 2000;
    }
    
    // Create gas sources
    // contract1 injected 300 gas, contract2 injected 700 gas
    // Total: 1000 gas
    let mut gas_sources = IndexMap::new();
    gas_sources.insert(Source::Contract(contract1.clone()), 300);
    gas_sources.insert(Source::Contract(contract2.clone()), 700);
    
    // Used gas: 600, max gas: 1000
    // Should refund: 1000 - 600 = 400
    // contract1 should get: 400 * 300/1000 = 120
    // contract2 should get: 400 * 700/1000 = 280
    refund_gas_sources(&mut state, gas_sources, 600, 1000).await.unwrap();
    
    // Check balances
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract1).await.unwrap();
        assert_eq!(*balance, 1120); // 1000 + 120 refund
    }
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract2).await.unwrap();
        assert_eq!(*balance, 2280); // 2000 + 280 refund
    }
}

#[tokio::test]
async fn test_refund_gas_sources_all_gas_used() {
    use crate::contract::{vm::refund_gas_sources, Source};

    let mut state = MockChainState::new();
    let contract = Hash::zero();
    
    // Initialize contract with balance
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract).await.unwrap();
        *balance = 1000;
    }
    
    // Create gas sources - contract injected 500 gas
    let mut gas_sources = IndexMap::new();
    gas_sources.insert(Source::Contract(contract.clone()), 500);
    
    // Used gas: 500, max gas: 500
    // Should refund: 0 (all gas was used)
    refund_gas_sources(&mut state, gas_sources, 500, 500).await.unwrap();
    
    // Check contract balance - should be unchanged
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract).await.unwrap();
        assert_eq!(*balance, 1000); // No refund
    }
}

#[tokio::test]
async fn test_refund_gas_sources_no_overflow() {
    use crate::contract::{vm::refund_gas_sources, Source};

    let mut state = MockChainState::new();
    let contract = Hash::zero();
    
    // Initialize contract with balance
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract).await.unwrap();
        *balance = 5000;
    }
    
    // Create gas sources - contract injected 1000 gas
    let mut gas_sources = IndexMap::new();
    gas_sources.insert(Source::Contract(contract.clone()), 1000);
    
    // Used gas exceeds max gas - should fail with overflow
    let result = refund_gas_sources(&mut state, gas_sources, 1200, 1000).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_refund_gas_sources_mixed_sources() {
    use crate::contract::{vm::refund_gas_sources, Source};
    use crate::crypto::KeyPair;

    let mut state = MockChainState::new();
    let contract = Hash::zero();
    let keypair = KeyPair::new();
    let account = keypair.get_public_key().compress();
    
    // Initialize contract with balance
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract).await.unwrap();
        *balance = 3000;
    }
    
    // Initialize account with balance
    {
        let balance_ct = keypair.get_public_key().encrypt(5000u64);
        state.accounts.insert(account.clone(), MockAccount {
            balances: [(XELIS_ASSET, balance_ct)].into_iter().collect(),
            nonce: 0,
        });
    }
    
    // Create gas sources
    // contract injected 600 gas, account paid 400 gas
    // Total: 1000 gas
    let mut gas_sources = IndexMap::new();
    gas_sources.insert(Source::Contract(contract.clone()), 600);
    gas_sources.insert(Source::Account(account.clone()), 400);
    
    // Used gas: 700, max gas: 1000
    // Should refund: 1000 - 700 = 300
    // contract should get: 300 * 600/1000 = 180
    // account should get: 300 * 400/1000 = 120
    refund_gas_sources(&mut state, gas_sources, 700, 1000).await.unwrap();
    
    // Check contract balance
    {
        let (_, balance) = state.get_contract_balance_for_gas(&contract).await.unwrap();
        assert_eq!(*balance, 3180); // 3000 + 180 refund
    }
    
    // Check account balance
    let balance_ct = &state.accounts.get(&account).unwrap().balances[&XELIS_ASSET];
    let balance_point = keypair.decrypt_to_point(balance_ct);

    assert_eq!(balance_point, Scalar::from(5120u64) * (*G)); // 5000 + 120 refund
}

#[tokio::test]
async fn test_refund_gas_sources_empty_sources() {
    use crate::contract::vm::refund_gas_sources;

    let mut state = MockChainState::new();
    
    // Empty gas sources - should not error
    let gas_sources = IndexMap::new();
    
    refund_gas_sources(&mut state, gas_sources, 500, 1000).await.unwrap();
    
    // Nothing should have changed
    assert!(state.contract_caches.is_empty());
}