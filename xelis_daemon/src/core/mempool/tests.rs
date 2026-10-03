use std::{borrow::Cow, collections::HashMap, sync::Arc};
use indexmap::IndexSet;
use xelis_common::{
    account::{CiphertextCache, VersionedBalance, VersionedNonce},
    config::{COIN_VALUE, FEE_PER_KB, XELIS_ASSET},
    crypto::{Address, Hash, Hashable},
    transaction::{
        MultiSigPayload,
        Reference,
        TxVersion,
        builder::{FeeBuilder, MultiSigBuilder, TransactionBuilder, TransactionTypeBuilder, TransferBuilder},
        mock::{TrackedAccount, TrackedAccountState, create_transfer_tx_for_account, create_multisig_transfer_tx},
        verify::VerificationError,
    },
    versioned::Versioned,
    network::Network,
};
use crate::core::{
    blockchain::ContractEnvironments,
    error::BlockchainError,
    storage::{MemoryStorage, BalanceProvider, MultiSigProvider, NonceProvider, AccountProvider},
};
use super::*;
use xelis_common::{serializer::Serializer, time::get_current_time_in_seconds};

#[tokio::test]
async fn test_commit_rejects_mismatched_sender_without_mutating_backend() {
    let alice = TrackedAccount::new();
    let mut bob = TrackedAccount::new();
    bob.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    let tx = Arc::new(create_transfer_tx_for_account(&mut bob, alice.address(), COIN_VALUE, None, TxVersion::V2, make_reference()).unwrap());
    let mempool = Mempool::new(Network::Devnet, false, 0, u64::MAX);
    let verification = mempool.begin_verification(&alice.get_public_key()).await;
    let mut backend = mempool.backend.write().await;
    let result = backend.store_verified(&verification, VerifiedTransaction {
        hash: Arc::new(tx.hash()),
        size: tx.size(),
        tx,
        fees: (FEE_PER_KB, FEE_PER_KB),
        balances: HashMap::new(),
        multisig: None,
    });
    assert!(matches!(result, Err(BlockchainError::MempoolSenderMismatch)));
    assert_eq!(backend.size(), 0);
    assert_eq!(backend.memory_usage(), 0);
    assert!(backend.get_caches().is_empty());
    assert!(backend.ordered_by_fee.is_empty());
    assert!(verification.is_current());
}

/// Setup a TrackedAccount in a MemoryStorage: registers the account, sets its nonce to 0,
/// and writes its encrypted balances so the chain-state verifier can find them.
async fn setup_account(storage: &mut MemoryStorage, account: &TrackedAccount) {
    let pk = account.get_public_key();

    for (asset, tracked_balance) in &account.balances {
        let mut cache = tracked_balance.ciphertext.clone();
        let ciphertext = cache.computable()
            .expect("ciphertext must be decompressible")
            .clone();
        let versioned_balance = VersionedBalance::new(
            CiphertextCache::Decompressed(None, ciphertext),
            None,
        );
        storage.set_last_balance_to(&pk, asset, 0, &versioned_balance).await
            .expect("set_last_balance_to failed");
    }
    storage.set_last_nonce_to(&pk, 0, &VersionedNonce::new(0, None)).await
        .expect("set_last_nonce_to failed");
    storage.set_account_registration_topoheight(&pk, 0).await
        .expect("set_account_registration_topoheight failed");
}

fn make_reference() -> Reference {
    Reference { topoheight: 0, hash: Hash::zero() }
}

async fn add_shared_tx(mempool: &Mempool, storage: &MemoryStorage, tx: Arc<Transaction>) -> Result<(), BlockchainError> {
    let hash = Arc::new(tx.hash());
    let size = tx.size();
    mempool.add_tx(storage, &ContractEnvironments::new(), 0, 0, FEE_PER_KB, 0, hash, tx, size, BlockVersion::V6).await.map(|_| ())
}

#[tokio::test]
async fn test_shared_admission_different_senders_do_not_wait_for_each_other() {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let mut alice = TrackedAccount::new();
    let mut bob = TrackedAccount::new();
    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    bob.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    setup_account(&mut storage, &alice).await;
    setup_account(&mut storage, &bob).await;
    let alice_tx = Arc::new(create_transfer_tx_for_account(&mut alice, bob.address(), COIN_VALUE, None, TxVersion::V2, make_reference()).unwrap());
    let bob_tx = Arc::new(create_transfer_tx_for_account(&mut bob, alice.address(), COIN_VALUE, None, TxVersion::V2, make_reference()).unwrap());
    let mempool = Mempool::new(Network::Devnet, false, 0, u64::MAX);
    let alice_verification = mempool.begin_verification(&alice.get_public_key()).await;

    let alice_add = add_shared_tx(&mempool, &storage, Arc::clone(&alice_tx));
    tokio::pin!(alice_add);
    assert!(futures::poll!(alice_add.as_mut()).is_pending());
    tokio::time::timeout(std::time::Duration::from_secs(5), add_shared_tx(&mempool, &storage, bob_tx)).await
        .expect("Bob must not wait for Alice's permit").unwrap();
    assert!(futures::poll!(alice_add.as_mut()).is_pending());
    assert_eq!(mempool.size().await, 1);

    drop(alice_verification);
    alice_add.await.unwrap();
    assert_eq!(mempool.size().await, 2);
    assert!(mempool.sender_locks.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_shared_admission_waiter_reads_updated_sender_cache() {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let mut alice = TrackedAccount::new();
    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    setup_account(&mut storage, &alice).await;
    let bob = TrackedAccount::new();
    let first = Arc::new(create_transfer_tx_for_account(&mut alice, bob.address(), COIN_VALUE, None, TxVersion::V2, make_reference()).unwrap());
    let second = Arc::new(create_transfer_tx_for_account(&mut alice, bob.address(), COIN_VALUE, None, TxVersion::V2, make_reference()).unwrap());
    let mempool = Mempool::new(Network::Devnet, false, 0, u64::MAX);
    let verification = mempool.begin_verification(&alice.get_public_key()).await;
    let second_add = add_shared_tx(&mempool, &storage, Arc::clone(&second));
    tokio::pin!(second_add);
    assert!(futures::poll!(second_add.as_mut()).is_pending());

    // Commit the predecessor while the next transaction is waiting. Its
    // snapshot must be taken only after it receives the sender permit.
    {
        let mut backend = mempool.backend.write().await;
        backend.add_tx(&storage, &ContractEnvironments::new(), 0, 0, FEE_PER_KB, 0, Arc::new(first.hash()), first.clone(), first.size(), BlockVersion::V6).await.unwrap();
    }
    drop(verification);
    second_add.await.unwrap();
    let backend = mempool.read().await;
    let cache = backend.get_cache_for(&alice.get_public_key()).unwrap();
    assert_eq!(cache.get_min(), 0);
    assert_eq!(cache.get_max(), 1);
    assert_eq!(cache.get_txs().len(), 2);
    assert_eq!(backend.memory_usage(), first.size() + second.size());
}

#[tokio::test]
async fn test_shared_admission_duplicate_is_committed_once() {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let mut alice = TrackedAccount::new();
    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    setup_account(&mut storage, &alice).await;
    let bob = TrackedAccount::new();
    let tx = Arc::new(create_transfer_tx_for_account(&mut alice, bob.address(), COIN_VALUE, None, TxVersion::V2, make_reference()).unwrap());
    let mempool = Mempool::new(Network::Devnet, false, 0, u64::MAX);
    let (first, second) = tokio::join!(add_shared_tx(&mempool, &storage, tx.clone()), add_shared_tx(&mempool, &storage, tx.clone()));
    assert!(matches!((first, second), (Ok(()), Err(BlockchainError::TxAlreadyInMempool(_))) | (Err(BlockchainError::TxAlreadyInMempool(_)), Ok(()))));
    assert_eq!(mempool.size().await, 1);
    assert_eq!(mempool.read().await.memory_usage(), tx.size());
    assert!(mempool.sender_locks.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_parallel_sender_admissions_keep_indexes_consistent() {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let mut alice = TrackedAccount::new();
    let mut bob = TrackedAccount::new();
    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    bob.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    setup_account(&mut storage, &alice).await;
    setup_account(&mut storage, &bob).await;
    let alice_tx = Arc::new(create_transfer_tx_for_account(&mut alice, bob.address(), COIN_VALUE, None, TxVersion::V2, make_reference()).unwrap());
    let bob_tx = Arc::new(create_transfer_tx_for_account(&mut bob, alice.address(), COIN_VALUE, None, TxVersion::V2, make_reference()).unwrap());
    let expected_size = alice_tx.size() + bob_tx.size();
    let mempool = Arc::new(Mempool::new(Network::Devnet, false, 0, u64::MAX));
    let storage = Arc::new(storage);
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let mut tasks = Vec::new();
    for tx in [alice_tx, bob_tx] {
        let mempool = Arc::clone(&mempool);
        let storage = Arc::clone(&storage);
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            add_shared_tx(&mempool, &storage, tx).await
        }));
    }
    for task in tasks {
        task.await.unwrap().unwrap();
    }
    let backend = mempool.read().await;
    assert_eq!(backend.size(), 2);
    assert_eq!(backend.memory_usage(), expected_size);
    assert_eq!(backend.ordered_by_fee.len(), 2);
    assert_eq!(backend.get_caches().len(), 2);
    assert!(mempool.sender_locks.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_eviction_rejects_verified_state_using_removed_predecessors() {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let mut alice = TrackedAccount::new();
    let mut bob = TrackedAccount::new();
    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    bob.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    setup_account(&mut storage, &alice).await;
    setup_account(&mut storage, &bob).await;
    let first = Arc::new(create_transfer_tx_for_account(&mut alice, bob.address(), COIN_VALUE, None, TxVersion::V2, make_reference()).unwrap());
    let second = Arc::new(create_transfer_tx_for_account(&mut alice, bob.address(), COIN_VALUE, None, TxVersion::V2, make_reference()).unwrap());
    let bob_tx = Arc::new(create_transfer_tx_for_account(&mut bob, alice.address(), COIN_VALUE, None, TxVersion::V2, make_reference()).unwrap());
    let mempool = Mempool::new(Network::Devnet, false, 0, u64::MAX);
    add_shared_tx(&mempool, &storage, first.clone()).await.unwrap();
    let mut verification = mempool.begin_verification(&alice.get_public_key()).await;
    let snapshot = {
        let backend = mempool.read().await;
        verification.revision = verification.revision_expected();
        backend.get_cache_for(&alice.get_public_key()).cloned().unwrap()
    };
    let alice_key = alice.get_public_key();
    let provider = MempoolProvider { cache: Some((&alice_key, &snapshot)), storage: &storage };
    let environments = ContractEnvironments::new();
    let mut state = ChainState::new(&provider, &environments, 0, 0, 0, BlockVersion::V6, FEE_PER_KB, 0);
    let tx_cache = TxCache::new(&storage, &mempool, false);
    let second_hash = Arc::new(second.hash());
    second.verify(&second_hash, &mut state, &tx_cache).await.unwrap();
    let (balances, multisig) = state.get_sender_cache(second.get_source()).unwrap();
    let fees = estimate_tx_fee_per_kb(&storage, 0, &second, second.size(), BlockVersion::V6).await.unwrap();

    {
        let mut backend = mempool.backend.write().await;
        backend.max_memory_usage = bob_tx.size() as u64;
        backend.store_tx(Arc::new(bob_tx.hash()), bob_tx.clone(), bob_tx.size(), (u64::MAX, u64::MAX), HashMap::new(), None).unwrap();
        assert!(!backend.contains_tx(&first.hash()));
        assert!(!verification.is_current());
        let result = backend.store_verified(&verification, VerifiedTransaction {
            hash: second_hash.clone(), tx: second.clone(), size: second.size(), fees, balances, multisig,
        });
        assert!(matches!(result, Err(BlockchainError::MempoolCacheChanged)));
        assert!(!backend.contains_tx(&second_hash));
        assert!(backend.get_cache_for(&alice_key).is_none());
        assert_eq!(backend.memory_usage(), bob_tx.size());
    }
    drop(verification);
    let err = add_shared_tx(&mempool, &storage, second).await.unwrap_err();
    assert!(matches!(err, BlockchainError::VerificationError(VerificationError::InvalidNonce(..))));
    assert!(mempool.sender_locks.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_cancelled_sender_waiter_preserves_semaphore_and_releases_registry() {
    let mempool = Mempool::new(Network::Devnet, false, 0, u64::MAX);
    let source = TrackedAccount::new().get_public_key();
    let verification = mempool.begin_verification(&source).await;
    {
        let waiting = mempool.begin_verification(&source);
        tokio::pin!(waiting);
        assert!(futures::poll!(waiting.as_mut()).is_pending());
    }
    assert_eq!(mempool.sender_locks.lock().unwrap().len(), 1);
    let another = mempool.sender_lease(&source);
    assert!(Arc::ptr_eq(another.lock.as_ref().unwrap(), verification.lease.lock.as_ref().unwrap()));
    drop(another);
    drop(verification);
    assert!(mempool.sender_locks.lock().unwrap().is_empty());
    let next = mempool.begin_verification(&source).await;
    assert_eq!(next.lease.lock().semaphore.available_permits(), 0);
}

#[tokio::test]
async fn test_add_valid_tx() {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);

    let mut alice = TrackedAccount::new();
    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    setup_account(&mut storage, &alice).await;

    let bob = TrackedAccount::new();
    let tx = create_transfer_tx_for_account(
        &mut alice,
        bob.address(),
        COIN_VALUE,
        None,
        TxVersion::V2,
        make_reference(),
    ).expect("failed to create transfer tx");

    let mut mempool = MempoolBackend::new(Network::Devnet, false, 0, u64::MAX);
    add_tx_to_mempool(&mut mempool, &storage, Arc::new(tx)).await
        .expect("add_tx should succeed for a valid TX");

    assert_eq!(mempool.size(), 1);
}

#[tokio::test]
async fn test_add_multiple_txs_same_source() {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);

    let mut alice = TrackedAccount::new();
    alice.set_balance(XELIS_ASSET, 500 * COIN_VALUE);
    setup_account(&mut storage, &alice).await;

    let bob = TrackedAccount::new();
    let mut mempool = MempoolBackend::new(Network::Devnet, false, 0, u64::MAX);

    for _ in 0..3 {
        let tx = create_transfer_tx_for_account(
            &mut alice,
            bob.address(),
            COIN_VALUE,
            None,
            TxVersion::V2,
            make_reference(),
        ).expect("failed to create transfer tx");

        add_tx_to_mempool(&mut mempool, &storage, Arc::new(tx)).await
            .expect("add_tx should succeed for sequential TXs from same source");
    }

    assert_eq!(mempool.size(), 3);
}

#[tokio::test]
async fn test_add_txs_different_sources() {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);

    let mut alice = TrackedAccount::new();
    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    setup_account(&mut storage, &alice).await;

    let mut bob = TrackedAccount::new();
    bob.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    setup_account(&mut storage, &bob).await;

    let carol = TrackedAccount::new();
    let mut mempool = MempoolBackend::new(Network::Devnet, false, 0, u64::MAX);

    let tx_a = create_transfer_tx_for_account(
        &mut alice,
        carol.address(),
        COIN_VALUE,
        None,
        TxVersion::V2,
        make_reference(),
    ).expect("alice tx failed");
    let tx_b = create_transfer_tx_for_account(
        &mut bob,
        carol.address(),
        COIN_VALUE,
        None,
        TxVersion::V2,
        make_reference(),
    ).expect("bob tx failed");

    for tx in [tx_a, tx_b] {
        add_tx_to_mempool(&mut mempool, &storage, Arc::new(tx)).await
            .expect("add_tx should succeed for different sources");
    }

    assert_eq!(mempool.size(), 2);
}

#[tokio::test]
async fn test_reject_duplicate_tx() {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);

    let mut alice = TrackedAccount::new();
    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    setup_account(&mut storage, &alice).await;

    let bob = TrackedAccount::new();

    let tx = create_transfer_tx_for_account(
        &mut alice,
        bob.address(),
        COIN_VALUE,
        None,
        TxVersion::V2,
        make_reference(),
    ).expect("failed to create transfer tx");

    let tx = Arc::new(tx);
    let mut mempool = MempoolBackend::new(Network::Devnet, false, 0, u64::MAX);

    // First add succeeds
    add_tx_to_mempool(&mut mempool, &storage, tx.clone()).await
        .expect("first add should succeed");

    // Second add with the same nonce should be rejected
    let err = add_tx_to_mempool(&mut mempool, &storage, tx.clone()).await
        .expect_err("duplicate nonce should be rejected");

    assert!(
        matches!(err, BlockchainError::VerificationError(VerificationError::InvalidNonce(..))),
        "expected VerificationError::InvalidNonce for duplicate nonce, got: {:?}", err
    );
}

#[test]
fn test_estimated_fee_rates() {
    // Let say we have the following TXs:
    // 0.0001 XEL per KB, 0.0002 XEL per KB, 0.0003 XEL per KB, 0.0004 XEL per KB, 0.0005 XEL per KB
    let fee_rates = vec![10000, 20000, 30000, 40000, 50000];
    let estimated = super::MempoolBackend::internal_estimate_fee_rates(fee_rates, FEE_PER_KB);
    assert_eq!(estimated.high, 50000);
    assert_eq!(estimated.medium, 35000);
    assert_eq!(estimated.low, 15000);
    assert_eq!(estimated.default, FEE_PER_KB);
}

#[test]
fn test_estimated_fee_rates_no_tx() {
    let estimated = super::MempoolBackend::internal_estimate_fee_rates(Vec::new(), FEE_PER_KB);
    assert_eq!(estimated.high, FEE_PER_KB);
    assert_eq!(estimated.medium, FEE_PER_KB);
    assert_eq!(estimated.low, FEE_PER_KB);
    assert_eq!(estimated.default, FEE_PER_KB);
}

#[test]
fn test_estimated_fee_rates_expensive_tx() {
    let fee_rates = vec![FEE_PER_KB * 1000];
    let estimated = super::MempoolBackend::internal_estimate_fee_rates(fee_rates, FEE_PER_KB);
    assert_eq!(estimated.high, FEE_PER_KB);
    assert_eq!(estimated.medium, FEE_PER_KB);
    assert_eq!(estimated.low, FEE_PER_KB);
    assert_eq!(estimated.default, FEE_PER_KB);

    let fee_rates = vec![FEE_PER_KB * 2, FEE_PER_KB * 2, FEE_PER_KB * 3, FEE_PER_KB * 2, FEE_PER_KB * 1000];
    let estimated = super::MempoolBackend::internal_estimate_fee_rates(fee_rates, FEE_PER_KB);
    assert_eq!(estimated.high, FEE_PER_KB * 1000);
    assert_eq!(estimated.medium, (FEE_PER_KB as f64 * 2.5) as u64);
    assert_eq!(estimated.low, FEE_PER_KB * 2);
    assert_eq!(estimated.default, FEE_PER_KB);
}

/// Build a MultiSig setup/delete TX from `account`, optionally signed by co-signers.
/// When `account` already has multisig configured, `signers` must carry the required co-sigs.
fn create_multisig_setup_tx(
    account: &mut TrackedAccount,
    participants: Vec<Address>,
    threshold: u8,
    signers: &[(u8, &TrackedAccount)],
) -> Transaction {
    let mut state = TrackedAccountState {
        balances: account.balances.clone(),
        nonce: account.nonce,
        reference: make_reference(),
    };
    let required_thresholds = if signers.is_empty() { None } else { Some(signers.len() as u8) };
    let builder = TransactionBuilder::new(
        TxVersion::V2,
        account.keypair.get_public_key().compress(),
        required_thresholds,
        TransactionTypeBuilder::MultiSig(MultiSigBuilder {
            participants: participants.into_iter().collect(),
            threshold,
        }),
        FeeBuilder::default(),
    );
    if signers.is_empty() {
        let tx = builder.build(&mut state, &account.keypair).unwrap();
        account.balances = state.balances;
        account.nonce = state.nonce;
        tx
    } else {
        let mut unsigned = builder.build_unsigned(&mut state, &account.keypair).unwrap();
        for (id, signer) in signers {
            unsigned.sign_multisig(&signer.keypair, *id);
        }
        let tx = unsigned.finalize(&account.keypair);
        account.balances = state.balances;
        account.nonce = state.nonce;
        tx
    }
}

/// Insert a MultiSigPayload directly into storage for an account.
async fn setup_multisig_in_storage(storage: &mut MemoryStorage, account: &TrackedAccount, payload: MultiSigPayload) {
    let pk = account.get_public_key();
    let versioned = Versioned::new(Some(Cow::Owned(payload)), None);
    storage.set_last_multisig_to(&pk, 0, versioned).await.unwrap();
}

/// Convenience wrapper: add a TX to the mempool with sensible defaults.
async fn add_tx_to_mempool(
    mempool: &mut MempoolBackend,
    storage: &MemoryStorage,
    tx: Arc<Transaction>,
) -> Result<(), BlockchainError> {
    let environments = ContractEnvironments::default();
    let hash = Arc::new(tx.hash());
    let size = tx.size();
    mempool.add_tx(storage, &environments, 0, 0, FEE_PER_KB, 0, hash, tx, size, BlockVersion::V6).await.map(|_| ())
}

async fn add_tx_to_mempool_internal_with_size(
    mempool: &mut MempoolBackend,
    storage: &MemoryStorage,
    tx: Arc<Transaction>,
    size: usize,
) -> Result<(), BlockchainError> {
    let hash = Arc::new(tx.hash());
    mempool.add_tx_internal(storage, 0, hash, tx, size, BlockVersion::V6, HashMap::new(), None).await
}

async fn cleanup_mempool(
    mempool: &mut MempoolBackend,
    storage: &MemoryStorage,
) -> Result<Vec<(Arc<Hash>, SortedTx)>, BlockchainError> {
    let environments = ContractEnvironments::default();
    mempool.clean_up(storage, &environments, 0, 0, BlockVersion::V6, FEE_PER_KB, 0, false).await
}

#[tokio::test]
async fn test_mempool_memory_limit_large_limit_keeps_all_txs() {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);

    let mut alice = TrackedAccount::new();
    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    setup_account(&mut storage, &alice).await;

    let mut bob = TrackedAccount::new();
    bob.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    setup_account(&mut storage, &bob).await;

    let carol = TrackedAccount::new();
    let tx_a = Arc::new(create_transfer_tx_for_account(
        &mut alice,
        carol.address(),
        COIN_VALUE,
        None,
        TxVersion::V2,
        make_reference(),
    ).expect("alice tx failed"));
    let tx_b = Arc::new(create_transfer_tx_for_account(
        &mut bob,
        carol.address(),
        COIN_VALUE,
        None,
        TxVersion::V2,
        make_reference(),
    ).expect("bob tx failed"));
    let expected_memory = tx_a.size() + tx_b.size();

    let mut mempool = MempoolBackend::new(Network::Devnet, false, 0, u64::MAX);
    add_tx_to_mempool(&mut mempool, &storage, tx_a).await.unwrap();
    add_tx_to_mempool(&mut mempool, &storage, tx_b).await.unwrap();

    assert_eq!(mempool.size(), 2);
    assert_eq!(mempool.memory_usage(), expected_memory);
}

#[tokio::test]
async fn test_mempool_memory_limit_below_single_tx_rejects_added_tx() {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);

    let mut alice = TrackedAccount::new();
    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    setup_account(&mut storage, &alice).await;

    let bob = TrackedAccount::new();
    let tx = Arc::new(create_transfer_tx_for_account(
        &mut alice,
        bob.address(),
        COIN_VALUE,
        None,
        TxVersion::V2,
        make_reference(),
    ).expect("transfer tx failed"));
    let hash = tx.hash();

    let mut mempool = MempoolBackend::new(Network::Devnet, false, 0, 0);
    let err = add_tx_to_mempool(&mut mempool, &storage, tx).await
        .expect_err("tx should be rejected when limit cannot keep it");

    assert!(matches!(err, BlockchainError::MempoolMemoryLimit));
    assert_eq!(mempool.size(), 0);
    assert_eq!(mempool.memory_usage(), 0);
    assert!(!mempool.contains_tx(&hash));
    assert!(mempool.get_cache_for(&alice.get_public_key()).is_none());
    assert!(mempool.ordered_by_fee.is_empty());
}

#[tokio::test]
async fn test_mempool_memory_limit_exact_limit_keeps_txs() {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);

    let mut alice = TrackedAccount::new();
    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    setup_account(&mut storage, &alice).await;

    let mut bob = TrackedAccount::new();
    bob.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    setup_account(&mut storage, &bob).await;

    let carol = TrackedAccount::new();
    let tx_a = Arc::new(create_transfer_tx_for_account(
        &mut alice,
        carol.address(),
        COIN_VALUE,
        None,
        TxVersion::V2,
        make_reference(),
    ).expect("alice tx failed"));
    let tx_b = Arc::new(create_transfer_tx_for_account(
        &mut bob,
        carol.address(),
        COIN_VALUE,
        None,
        TxVersion::V2,
        make_reference(),
    ).expect("bob tx failed"));
    let tx_a_size = tx_a.size();
    let tx_b_size = tx_b.size();

    let mut mempool = MempoolBackend::new(Network::Devnet, false, 0, (tx_a_size + tx_b_size) as u64);
    add_tx_to_mempool(&mut mempool, &storage, tx_a).await.unwrap();
    add_tx_to_mempool(&mut mempool, &storage, tx_b).await.unwrap();

    assert_eq!(mempool.size(), 2);
    assert_eq!(mempool.memory_usage(), tx_a_size + tx_b_size);
}

#[tokio::test]
async fn test_mempool_memory_limit_evicts_lowest_fee_rate_first() {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);

    let mut alice = TrackedAccount::new();
    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    setup_account(&mut storage, &alice).await;

    let mut bob = TrackedAccount::new();
    bob.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    setup_account(&mut storage, &bob).await;

    let carol = TrackedAccount::new();
    let low_fee_tx = Arc::new(create_transfer_tx_for_account(
        &mut alice,
        carol.address(),
        COIN_VALUE,
        None,
        TxVersion::V2,
        make_reference(),
    ).expect("low fee tx failed"));
    let high_fee_tx = Arc::new(create_transfer_tx_for_account(
        &mut bob,
        carol.address(),
        COIN_VALUE,
        None,
        TxVersion::V2,
        make_reference(),
    ).expect("high fee tx failed"));
    let low_hash = low_fee_tx.hash();
    let high_hash = high_fee_tx.hash();
    let low_size = low_fee_tx.size() + 2048;
    let high_size = high_fee_tx.size();

    let mut mempool = MempoolBackend::new(Network::Devnet, false, 0, low_size as u64);
    add_tx_to_mempool_internal_with_size(&mut mempool, &storage, low_fee_tx, low_size).await.unwrap();
    add_tx_to_mempool_internal_with_size(&mut mempool, &storage, high_fee_tx, high_size).await.unwrap();

    assert_eq!(mempool.size(), 1);
    assert_eq!(mempool.memory_usage(), high_size);
    assert!(!mempool.contains_tx(&low_hash));
    assert!(mempool.contains_tx(&high_hash));
    assert!(mempool.get_cache_for(&alice.get_public_key()).is_none());
    assert!(mempool.get_cache_for(&bob.get_public_key()).is_some());
}

#[tokio::test]
async fn test_mempool_memory_limit_rejects_new_low_fee_tx_and_keeps_existing() {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);

    let mut alice = TrackedAccount::new();
    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    setup_account(&mut storage, &alice).await;

    let mut bob = TrackedAccount::new();
    bob.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    setup_account(&mut storage, &bob).await;

    let carol = TrackedAccount::new();
    let existing_tx = Arc::new(create_transfer_tx_for_account(
        &mut alice,
        carol.address(),
        COIN_VALUE,
        None,
        TxVersion::V2,
        make_reference(),
    ).expect("existing tx failed"));
    let new_low_fee_tx = Arc::new(create_transfer_tx_for_account(
        &mut bob,
        carol.address(),
        COIN_VALUE,
        None,
        TxVersion::V2,
        make_reference(),
    ).expect("new low fee tx failed"));
    let existing_hash = existing_tx.hash();
    let new_hash = new_low_fee_tx.hash();
    let existing_size = existing_tx.size();
    let new_low_fee_size = new_low_fee_tx.size() + 4096;

    let mut mempool = MempoolBackend::new(Network::Devnet, false, 0, existing_size as u64);
    add_tx_to_mempool_internal_with_size(&mut mempool, &storage, existing_tx, existing_size).await.unwrap();
    let err = add_tx_to_mempool_internal_with_size(&mut mempool, &storage, new_low_fee_tx, new_low_fee_size).await
        .expect_err("new low-fee TX should be evicted and rejected");

    assert!(matches!(err, BlockchainError::MempoolMemoryLimit));
    assert_eq!(mempool.size(), 1);
    assert_eq!(mempool.memory_usage(), existing_size);
    assert!(mempool.contains_tx(&existing_hash));
    assert!(!mempool.contains_tx(&new_hash));
    assert!(mempool.get_cache_for(&alice.get_public_key()).is_some());
    assert!(mempool.get_cache_for(&bob.get_public_key()).is_none());
}

#[tokio::test]
async fn test_mempool_memory_limit_evicts_multiple_low_fee_accounts() {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);

    let mut alice = TrackedAccount::new();
    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    setup_account(&mut storage, &alice).await;

    let mut bob = TrackedAccount::new();
    bob.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    setup_account(&mut storage, &bob).await;

    let mut carol = TrackedAccount::new();
    carol.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    setup_account(&mut storage, &carol).await;

    let destination = TrackedAccount::new();
    let low_fee_tx_a = Arc::new(create_transfer_tx_for_account(
        &mut alice,
        destination.address(),
        COIN_VALUE,
        None,
        TxVersion::V2,
        make_reference(),
    ).expect("first low fee tx failed"));
    let low_fee_tx_b = Arc::new(create_transfer_tx_for_account(
        &mut bob,
        destination.address(),
        COIN_VALUE,
        None,
        TxVersion::V2,
        make_reference(),
    ).expect("second low fee tx failed"));
    let high_fee_tx = Arc::new(create_transfer_tx_for_account(
        &mut carol,
        destination.address(),
        COIN_VALUE,
        None,
        TxVersion::V2,
        make_reference(),
    ).expect("high fee tx failed"));

    let low_hash_a = low_fee_tx_a.hash();
    let low_hash_b = low_fee_tx_b.hash();
    let high_hash = high_fee_tx.hash();
    let low_size_a = low_fee_tx_a.size() + 4096;
    let low_size_b = low_fee_tx_b.size() + 4096;
    let high_size = high_fee_tx.size();

    let mut mempool = MempoolBackend::new(Network::Devnet, false, 0, high_size as u64);
    add_tx_to_mempool_internal_with_size(&mut mempool, &storage, low_fee_tx_a.clone(), low_size_a).await
        .expect_err("first oversized low-fee TX should not fit by itself");

    // Use a fresh pool so we can verify multi-eviction after two low-fee accounts are already present.
    let mut mempool = MempoolBackend::new(Network::Devnet, false, 0, (low_size_a + low_size_b + high_size) as u64);
    add_tx_to_mempool_internal_with_size(&mut mempool, &storage, low_fee_tx_b.clone(), low_size_b).await.unwrap();
    add_tx_to_mempool_internal_with_size(&mut mempool, &storage, low_fee_tx_a.clone(), low_size_a).await.unwrap();
    mempool.max_memory_usage = high_size as u64;
    add_tx_to_mempool_internal_with_size(&mut mempool, &storage, high_fee_tx, high_size).await.unwrap();

    assert_eq!(mempool.size(), 1);
    assert_eq!(mempool.memory_usage(), high_size);
    assert!(!mempool.contains_tx(&low_hash_a));
    assert!(!mempool.contains_tx(&low_hash_b));
    assert!(mempool.contains_tx(&high_hash));
    assert!(mempool.get_cache_for(&alice.get_public_key()).is_none());
    assert!(mempool.get_cache_for(&bob.get_public_key()).is_none());
    assert!(mempool.get_cache_for(&carol.get_public_key()).is_some());
}

#[tokio::test]
async fn test_mempool_memory_limit_evicts_whole_nonce_chain() {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);

    let mut alice = TrackedAccount::new();
    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    setup_account(&mut storage, &alice).await;

    let mut bob = TrackedAccount::new();
    bob.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    setup_account(&mut storage, &bob).await;

    let carol = TrackedAccount::new();
    let alice_first_tx = Arc::new(create_transfer_tx_for_account(
        &mut alice,
        carol.address(),
        COIN_VALUE,
        None,
        TxVersion::V2,
        make_reference(),
    ).expect("alice first tx failed"));
    let alice_second_tx = Arc::new(create_transfer_tx_for_account(
        &mut alice,
        carol.address(),
        COIN_VALUE,
        None,
        TxVersion::V2,
        make_reference(),
    ).expect("alice second tx failed"));
    let bob_tx = Arc::new(create_transfer_tx_for_account(
        &mut bob,
        carol.address(),
        COIN_VALUE,
        None,
        TxVersion::V2,
        make_reference(),
    ).expect("bob tx failed"));

    let alice_first_hash = alice_first_tx.hash();
    let alice_second_hash = alice_second_tx.hash();
    let bob_hash = bob_tx.hash();

    let alice_first_size = alice_first_tx.size() + 4096;
    let alice_second_size = alice_second_tx.size() + 4096;
    let bob_size = bob_tx.size();

    let mut mempool = MempoolBackend::new(Network::Devnet, false, 0, (alice_first_size + alice_second_size) as u64);
    add_tx_to_mempool_internal_with_size(&mut mempool, &storage, alice_first_tx, alice_first_size).await.unwrap();
    add_tx_to_mempool_internal_with_size(&mut mempool, &storage, alice_second_tx, alice_second_size).await.unwrap();
    add_tx_to_mempool_internal_with_size(&mut mempool, &storage, bob_tx, bob_size).await.unwrap();

    assert_eq!(mempool.size(), 1);
    assert_eq!(mempool.memory_usage(), bob_size);
    assert!(!mempool.contains_tx(&alice_first_hash));
    assert!(!mempool.contains_tx(&alice_second_hash));
    assert!(mempool.contains_tx(&bob_hash));
    assert!(mempool.get_cache_for(&alice.get_public_key()).is_none());
    assert!(mempool.get_cache_for(&bob.get_public_key()).is_some());
}

#[tokio::test]
async fn test_mempool_expiration_disabled_keeps_old_tx() {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);

    let mut alice = TrackedAccount::new();
    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    setup_account(&mut storage, &alice).await;

    let bob = TrackedAccount::new();
    let tx = Arc::new(create_transfer_tx_for_account(
        &mut alice,
        bob.address(),
        COIN_VALUE,
        None,
        TxVersion::V2,
        make_reference(),
    ).expect("transfer tx failed"));
    let hash = Arc::new(tx.hash());

    let mut mempool = MempoolBackend::new(Network::Devnet, false, 0, u64::MAX);
    add_tx_to_mempool(&mut mempool, &storage, tx).await.unwrap();
    mempool.txs.get_mut(&hash).unwrap().first_seen = get_current_time_in_seconds().saturating_sub(3600);

    let deleted = cleanup_mempool(&mut mempool, &storage).await.unwrap();

    assert!(deleted.is_empty());
    assert_eq!(mempool.size(), 1);
    assert!(mempool.contains_tx(&hash));
}

#[tokio::test]
async fn test_mempool_expiration_removes_expired_tx() {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);

    let mut alice = TrackedAccount::new();
    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    setup_account(&mut storage, &alice).await;

    let bob = TrackedAccount::new();
    let tx = Arc::new(create_transfer_tx_for_account(
        &mut alice,
        bob.address(),
        COIN_VALUE,
        None,
        TxVersion::V2,
        make_reference(),
    ).expect("transfer tx failed"));
    let hash = Arc::new(tx.hash());

    let mut mempool = MempoolBackend::new(Network::Devnet, false, 1, u64::MAX);
    add_tx_to_mempool(&mut mempool, &storage, tx).await.unwrap();
    mempool.txs.get_mut(&hash).unwrap().first_seen = get_current_time_in_seconds().saturating_sub(2);

    let deleted = cleanup_mempool(&mut mempool, &storage).await.unwrap();

    assert_eq!(deleted.len(), 1);
    assert_eq!(deleted[0].0, hash);
    assert_eq!(mempool.size(), 0);
    assert_eq!(mempool.memory_usage(), 0);
    assert!(!mempool.contains_tx(&hash));
    assert!(mempool.ordered_by_fee.is_empty());
}

#[tokio::test]
async fn test_mempool_expiration_keeps_fresh_account() {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);

    let mut alice = TrackedAccount::new();
    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    setup_account(&mut storage, &alice).await;

    let mut bob = TrackedAccount::new();
    bob.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    setup_account(&mut storage, &bob).await;

    let carol = TrackedAccount::new();
    let expired_tx = Arc::new(create_transfer_tx_for_account(
        &mut alice,
        carol.address(),
        COIN_VALUE,
        None,
        TxVersion::V2,
        make_reference(),
    ).expect("expired tx failed"));
    let fresh_tx = Arc::new(create_transfer_tx_for_account(
        &mut bob,
        carol.address(),
        COIN_VALUE,
        None,
        TxVersion::V2,
        make_reference(),
    ).expect("fresh tx failed"));
    let expired_hash = Arc::new(expired_tx.hash());
    let fresh_hash = Arc::new(fresh_tx.hash());
    let fresh_size = fresh_tx.size();

    let mut mempool = MempoolBackend::new(Network::Devnet, false, 10, u64::MAX);
    add_tx_to_mempool(&mut mempool, &storage, expired_tx).await.unwrap();
    add_tx_to_mempool(&mut mempool, &storage, fresh_tx).await.unwrap();
    mempool.txs.get_mut(&expired_hash).unwrap().first_seen = get_current_time_in_seconds().saturating_sub(10);

    let deleted = cleanup_mempool(&mut mempool, &storage).await.unwrap();

    assert_eq!(deleted.len(), 1);
    assert_eq!(deleted[0].0, expired_hash);
    assert_eq!(mempool.size(), 1);
    assert_eq!(mempool.memory_usage(), fresh_size);
    assert!(!mempool.contains_tx(&expired_hash));
    assert!(mempool.contains_tx(&fresh_hash));
}

#[tokio::test]
async fn test_mempool_expiration_removes_nonce_chain_after_expired_head() {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);

    let mut alice = TrackedAccount::new();
    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    setup_account(&mut storage, &alice).await;

    let bob = TrackedAccount::new();
    let first_tx = Arc::new(create_transfer_tx_for_account(
        &mut alice,
        bob.address(),
        COIN_VALUE,
        None,
        TxVersion::V2,
        make_reference(),
    ).expect("first tx failed"));
    let second_tx = Arc::new(create_transfer_tx_for_account(
        &mut alice,
        bob.address(),
        COIN_VALUE,
        None,
        TxVersion::V2,
        make_reference(),
    ).expect("second tx failed"));
    let first_hash = Arc::new(first_tx.hash());
    let second_hash = Arc::new(second_tx.hash());

    let mut mempool = MempoolBackend::new(Network::Devnet, false, 10, u64::MAX);
    add_tx_to_mempool(&mut mempool, &storage, first_tx).await.unwrap();
    add_tx_to_mempool(&mut mempool, &storage, second_tx).await.unwrap();
    mempool.txs.get_mut(&first_hash).unwrap().first_seen = get_current_time_in_seconds().saturating_sub(10);

    let deleted = cleanup_mempool(&mut mempool, &storage).await.unwrap();
    let deleted_hashes: IndexSet<_> = deleted.into_iter()
        .map(|(hash, _)| hash)
        .collect();

    assert_eq!(deleted_hashes.len(), 2);
    assert!(deleted_hashes.contains(&first_hash));
    assert!(deleted_hashes.contains(&second_hash));
    assert_eq!(mempool.size(), 0);
    assert_eq!(mempool.memory_usage(), 0);
    assert!(mempool.get_cache_for(&alice.get_public_key()).is_none());
    assert!(mempool.ordered_by_fee.is_empty());
}

/// A MultiSig setup TX (configuring multisig on `alice`) should be accepted by the mempool.
#[tokio::test]
async fn test_multisig_setup_tx() {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let mempool = Mempool::new(Network::Devnet, false, 0, u64::MAX);

    let mut alice = TrackedAccount::new();
    alice.set_balance(XELIS_ASSET, COIN_VALUE * 100);
    setup_account(&mut storage, &alice).await;

    let bob = TrackedAccount::new();
    let carol = TrackedAccount::new();

    let participants = vec![bob.address(), carol.address()];
    let tx = create_multisig_setup_tx(&mut alice, participants, 2, &[]);
    let result = add_shared_tx(&mempool, &storage, Arc::new(tx)).await;
    assert!(result.is_ok(), "multisig setup TX should be accepted: {:?}", result.err());
}

/// A transfer from an account with multisig configured in storage should be accepted
/// when the TX carries the correct multisig signatures.
#[tokio::test]
async fn test_transfer_with_valid_multisig() {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let mempool = Mempool::new(Network::Devnet, false, 0, u64::MAX);

    let mut alice = TrackedAccount::new();
    alice.set_balance(XELIS_ASSET, COIN_VALUE * 100);
    setup_account(&mut storage, &alice).await;

    let bob = TrackedAccount::new();
    let carol = TrackedAccount::new();

    // Pre-configure alice's account with 2-of-2 multisig (bob=0, carol=1)
    let payload = MultiSigPayload {
        threshold: 2,
        participants: [bob.get_public_key(), carol.get_public_key()].into_iter().collect(),
    };
    setup_multisig_in_storage(&mut storage, &alice, payload).await;

    // (id=0 => bob, id=1 => carol)
    let tx = create_multisig_transfer_tx(&mut alice, bob.address(), COIN_VALUE, &[(0, &bob), (1, &carol)], TxVersion::V2, make_reference());
    let result = add_shared_tx(&mempool, &storage, Arc::new(tx)).await;
    assert!(result.is_ok(), "transfer with valid multisig should be accepted: {:?}", result.err());
}

/// A transfer from a multisig-configured account that carries NO multisig field
/// should be rejected with `MultiSigNotFound`.
#[tokio::test]
async fn test_transfer_without_multisig_fails() {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let mempool = Mempool::new(Network::Devnet, false, 0, u64::MAX);

    let mut alice = TrackedAccount::new();
    alice.set_balance(XELIS_ASSET, COIN_VALUE * 100);
    setup_account(&mut storage, &alice).await;

    let bob = TrackedAccount::new();
    let carol = TrackedAccount::new();

    let payload = MultiSigPayload {
        threshold: 2,
        participants: [bob.get_public_key(), carol.get_public_key()].into_iter().collect(),
    };
    setup_multisig_in_storage(&mut storage, &alice, payload).await;

    // Normal transfer: no multisig signatures attached
    let tx = create_transfer_tx_for_account(
        &mut alice, bob.address(), COIN_VALUE, None, TxVersion::V2, make_reference()
    ).unwrap();

    let err = add_shared_tx(&mempool, &storage, Arc::new(tx)).await.unwrap_err();
    assert!(
        matches!(err, BlockchainError::VerificationError(VerificationError::MultiSigNotFound)),
        "expected MultiSigNotFound, got: {:?}", err
    );
}

/// A transfer from a multisig account with fewer signatures than the threshold
/// should be rejected with `MultiSigParticipants`.
#[tokio::test]
async fn test_transfer_with_wrong_sig_count_fails() {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let mempool = Mempool::new(Network::Devnet, false, 0, u64::MAX);

    let mut alice = TrackedAccount::new();
    alice.set_balance(XELIS_ASSET, COIN_VALUE * 100);
    setup_account(&mut storage, &alice).await;

    let bob = TrackedAccount::new();
    let carol = TrackedAccount::new();

    // threshold=2 but we'll only attach 1 signature
    let payload = MultiSigPayload {
        threshold: 2,
        participants: [bob.get_public_key(), carol.get_public_key()].into_iter().collect(),
    };
    setup_multisig_in_storage(&mut storage, &alice, payload).await;

    // Only sign with bob (id=0), missing carol
    let tx = create_multisig_transfer_tx(&mut alice, bob.address(), COIN_VALUE, &[(0, &bob)], TxVersion::V2, make_reference());
    let err = add_shared_tx(&mempool, &storage, Arc::new(tx)).await.unwrap_err();
    assert!(
        matches!(err, BlockchainError::VerificationError(VerificationError::MultiSigParticipants)),
        "expected MultiSigParticipants, got: {:?}", err
    );
}

/// A transfer from an account WITHOUT multisig configured but carrying a multisig field
/// should be rejected with `MultiSigNotConfigured`.
#[tokio::test]
async fn test_tx_with_multisig_but_not_configured_fails() {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let mempool = Mempool::new(Network::Devnet, false, 0, u64::MAX);

    let mut alice = TrackedAccount::new();
    alice.set_balance(XELIS_ASSET, COIN_VALUE * 100);
    setup_account(&mut storage, &alice).await;

    let bob = TrackedAccount::new();

    // No multisig configured in storage for alice.
    // Create a transfer TX with multisig sigs (as if alice had 1-of-1 multisig with bob).
    let tx = create_multisig_transfer_tx(&mut alice, bob.address(), COIN_VALUE, &[(0, &bob)], TxVersion::V2, make_reference());
    let err = add_shared_tx(&mempool, &storage, Arc::new(tx)).await.unwrap_err();
    assert!(
        matches!(err, BlockchainError::VerificationError(VerificationError::MultiSigNotConfigured)),
        "expected MultiSigNotConfigured, got: {:?}", err
    );
}

/// A delete/reset multisig TX (threshold=0, no participants) from an account that HAS multisig
/// configured should be accepted.
#[tokio::test]
async fn test_multisig_delete_tx() {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let mempool = Mempool::new(Network::Devnet, false, 0, u64::MAX);

    let mut alice = TrackedAccount::new();
    alice.set_balance(XELIS_ASSET, COIN_VALUE * 100);
    setup_account(&mut storage, &alice).await;

    let bob = TrackedAccount::new();

    // Configure multisig first
    let payload = MultiSigPayload {
        threshold: 1,
        participants: [bob.get_public_key()].into_iter().collect(),
    };
    setup_multisig_in_storage(&mut storage, &alice, payload).await;

    // Delete multisig: threshold=0, no participants — but bob must co-sign since threshold=1
    let delete_tx = create_multisig_setup_tx(&mut alice, vec![], 0, &[(0, &bob)]);
    let result = add_shared_tx(&mempool, &storage, Arc::new(delete_tx)).await;
    assert!(result.is_ok(), "multisig delete TX should be accepted: {:?}", result.err());
}

/// A delete/reset multisig TX from an account that does NOT have multisig configured
/// should be rejected with `MultiSigNotConfigured`.
#[tokio::test]
async fn test_multisig_delete_without_config_fails() {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let mempool = Mempool::new(Network::Devnet, false, 0, u64::MAX);

    let mut alice = TrackedAccount::new();
    alice.set_balance(XELIS_ASSET, COIN_VALUE * 100);
    setup_account(&mut storage, &alice).await;

    // No multisig configured — try to delete/reset
    let delete_tx = create_multisig_setup_tx(&mut alice, vec![], 0, &[]);
    let err = add_shared_tx(&mempool, &storage, Arc::new(delete_tx)).await.unwrap_err();
    assert!(
        matches!(err, BlockchainError::VerificationError(VerificationError::MultiSigNotConfigured)),
        "expected MultiSigNotConfigured, got: {:?}", err
    );
}

/// After setting up multisig via TX and then deleting it via a follow-up TX, subsequent
/// normal transfers (without multisig sigs) should be accepted again.
#[tokio::test]
async fn test_multisig_setup_then_delete_allows_normal_transfer() {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let mempool = Mempool::new(Network::Devnet, false, 0, u64::MAX);

    let mut alice = TrackedAccount::new();
    alice.set_balance(XELIS_ASSET, COIN_VALUE * 100);
    setup_account(&mut storage, &alice).await;

    let bob = TrackedAccount::new();
    let carol = TrackedAccount::new();

    // 1. Setup multisig (1-of-1 with bob)
    let setup_tx = create_multisig_setup_tx(&mut alice, vec![bob.address()], 1, &[]);
    add_shared_tx(&mempool, &storage, Arc::new(setup_tx)).await.unwrap();

    // 2. Delete multisig — alice now has 1-of-1 multisig (bob), so bob must co-sign the delete TX
    let delete_tx = create_multisig_setup_tx(&mut alice, vec![], 0, &[(0, &bob)]);
    add_shared_tx(&mempool, &storage, Arc::new(delete_tx)).await.unwrap();

    // 3. Normal transfer: no multisig signatures needed (multisig is now deleted in cache)
    let tx = create_transfer_tx_for_account(
        &mut alice, carol.address(), COIN_VALUE, None, TxVersion::V2, make_reference()
    ).unwrap();
    let result = add_shared_tx(&mempool, &storage, Arc::new(tx)).await;
    assert!(result.is_ok(), "normal transfer after multisig delete should be accepted: {:?}", result.err());
}

#[tokio::test]
async fn test_shared_admission_preserves_untouched_asset_balances() {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let mut alice = TrackedAccount::new();
    let bob = TrackedAccount::new();
    let asset_a = Hash::new([1; 32]);
    let asset_b = Hash::new([2; 32]);
    for asset in [XELIS_ASSET, asset_a.clone(), asset_b.clone()] {
        alice.set_balance(asset, 100 * COIN_VALUE);
    }
    setup_account(&mut storage, &alice).await;
    let mempool = Mempool::new(Network::Devnet, false, 0, u64::MAX);

    // Each verification only loads the current transfer asset and XELIS for fees.
    // The third transaction must use A's pending balance from the first one.
    for asset in [asset_a.clone(), asset_b.clone(), asset_a.clone()] {
        let mut state = TrackedAccountState {
            balances: alice.balances.clone(), nonce: alice.nonce, reference: make_reference(),
        };
        let builder = TransactionBuilder::new(
            TxVersion::V2, alice.keypair.get_public_key().compress(), None,
            TransactionTypeBuilder::Transfers(vec![TransferBuilder {
                amount: COIN_VALUE, destination: bob.address(), asset,
                extra_data: None, encrypt_extra_data: true,
            }]), FeeBuilder::default(),
        );
        let tx = builder.build(&mut state, &alice.keypair).unwrap();
        alice.balances = state.balances;
        alice.nonce = state.nonce;
        add_shared_tx(&mempool, &storage, Arc::new(tx)).await.unwrap();
    }
    let backend = mempool.read().await;
    let cache = backend.get_cache_for(&alice.get_public_key()).unwrap();
    assert_eq!(cache.get_txs().len(), 3);
    for asset in [XELIS_ASSET, asset_a, asset_b] {
        let mut expected = alice.balances.get(&asset).unwrap().ciphertext.clone();
        assert_eq!(cache.get_balances().get(&asset).unwrap(), expected.computable().unwrap());
    }
}

#[tokio::test]
async fn test_admission_metadata_survives_eviction() {
    let mut storage = MemoryStorage::new(Network::Devnet, 1);
    let mut alice = TrackedAccount::new();
    let mut bob = TrackedAccount::new();
    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    bob.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    setup_account(&mut storage, &alice).await;
    let tx = Arc::new(create_transfer_tx_for_account(&mut alice, bob.address(), COIN_VALUE, None, TxVersion::V2, make_reference()).unwrap());
    let hash = Arc::new(tx.hash());
    let mempool = Mempool::new(Network::Devnet, false, 0, u64::MAX);
    let metadata = mempool.add_tx(&storage, &ContractEnvironments::new(), 0, 0, FEE_PER_KB, 0, hash.clone(), tx.clone(), tx.size(), BlockVersion::V6).await.unwrap();
    let first_seen = metadata.get_first_seen();
    let fees = estimate_tx_fee_per_kb(&storage, 0, &tx, tx.size(), BlockVersion::V6).await.unwrap();
    let bob_tx = Arc::new(create_transfer_tx_for_account(&mut bob, alice.address(), COIN_VALUE, None, TxVersion::V2, make_reference()).unwrap());
    {
        let mut backend = mempool.backend.write().await;
        backend.max_memory_usage = bob_tx.size() as u64;
        backend.store_tx(Arc::new(bob_tx.hash()), bob_tx.clone(), bob_tx.size(), (u64::MAX, u64::MAX), HashMap::new(), None).unwrap();
        assert!(!backend.contains_tx(&hash));
    }
    // Notification serialization needs no further mempool lookup after eviction.
    let json = serde_json::to_value(&metadata).unwrap();
    assert_eq!(json["size"], tx.size());
    assert_eq!(json["first_seen"], first_seen);
    assert_eq!(metadata.get_fee_per_kb(), fees.0);
    assert!(Arc::ptr_eq(metadata.get_tx(), &tx));
}
