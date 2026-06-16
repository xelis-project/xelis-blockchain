use std::{collections::HashMap, sync::Arc};
use anyhow::Context;
use async_trait::async_trait;
use curve25519_dalek::Scalar;
use indexmap::IndexSet;
use xelis_vm::{Chunk, Module};
use crate::{
    account::{CiphertextCache, Nonce},
    api::{DataElement, DataValue},
    config::{BURN_PER_CONTRACT, COIN_VALUE, XELIS_ASSET},
    contract::ContractModule,
    crypto::{
        elgamal::{Ciphertext, PedersenOpening},
        proofs::{G, ProofVerificationError},
        Address,
        Hash,
        Hashable,
        PublicKey
    },
    serializer::Serializer,
    transaction::{
        builder::{
            AccountState,
            BlobPayloadBuilder,
            ContractDepositBuilder,
            DeployContractBuilder,
            DeployContractInvokeBuilder,
            FeeBuilder,
            FeeHelper,
            GenerationError,
            GenerationStateError,
            InvokeContractBuilder,
            MultiSigBuilder,
            TransactionBuilder,
            TransactionTypeBuilder,
            TransferBuilder
        },
        extra_data::{
            derive_shared_key_from_opening,
            PlaintextData
        },
        verify::{NoZKPCache, VerificationError, VerificationStateError, ZKPCache},
        mock::*,
        BlobPayload,
        BurnPayload,
        MultiSigPayload,
        Reference,
        Role,
        Transaction,
        TransactionType,
        TxVersion,
        MAX_TRANSFER_COUNT
    },
};

pub struct AccountStateImpl {
    pub balances: HashMap<Hash, TrackedBalance>,
    pub reference: Reference,
    pub nonce: Nonce,
}

fn create_tx_for(mut account: TrackedAccount, destination: Address, amount: u64, extra_data: Option<DataElement>) -> Arc<Transaction> {
    let reference = Reference {
        topoheight: 0,
        hash: Hash::zero(),
    };

    let balance_before = account.get_balance(&XELIS_ASSET).unwrap();
    let tx = create_transfer_tx_for_account(
        &mut account,
        destination,
        amount,
        extra_data,
        TxVersion::V1,
        reference,
    ).unwrap();
    
    assert!(tx.fee * 2 == tx.fee_limit);
    let total_spend = amount + tx.fee_limit;
    let balance_after = account.get_balance(&XELIS_ASSET).unwrap();
    let expected_balance = balance_before - total_spend;
    assert!(balance_after == expected_balance, "expected balance {} got {}", expected_balance, balance_after);

    Arc::new(tx)
}

#[test]
fn test_encrypt_decrypt() {
    let r = PedersenOpening::generate_new();
    let key = derive_shared_key_from_opening(&r);
    let message = "Hello, World!".as_bytes().to_vec();

    let plaintext = PlaintextData(message.clone());
    let cipher = plaintext.encrypt_in_place_with_aead(&key);
    let decrypted = cipher.decrypt_in_place(&key).unwrap();

    assert_eq!(decrypted.0, message);
}

#[test]
fn test_encrypt_decrypt_two_parties() {
    let mut alice = TrackedAccount::new();
    alice.balances.insert(XELIS_ASSET, TrackedBalance {
        balance: 100 * COIN_VALUE,
        ciphertext: CiphertextCache::Decompressed(None, alice.keypair.get_public_key().encrypt(100 * COIN_VALUE)),
    });

    let bob = TrackedAccount::new();

    let payload = DataElement::Value(DataValue::String("Hello, World!".to_string()));
    let tx = create_tx_for(alice.clone(), bob.address(), 50, Some(payload.clone()));
    let TransactionType::Transfers(transfers) = tx.get_data() else {
        unreachable!()
    };

    let transfer = &transfers[0];
    let cipher = transfer.get_extra_data().clone().unwrap();
    // Verify the extra data from alice (sender)
    {
        let decrypted = cipher.decrypt(&alice.keypair.get_private_key(), None, Role::Sender, TxVersion::V1).unwrap();
        assert_eq!(decrypted.data(), Some(&payload));
    }

    // Verify the extra data from bob (receiver)
    {
        let decrypted = cipher.decrypt(&bob.keypair.get_private_key(), None, Role::Receiver, TxVersion::V1).unwrap();
        assert_eq!(decrypted.data(), Some(&payload));
    }

    // Verify the extra data from alice (sender) with the wrong key
    {
        let decrypted = cipher.decrypt(&bob.keypair.get_private_key(), None, Role::Sender, TxVersion::V1);
        assert!(decrypted.is_err());
    }
}

#[tokio::test]
async fn test_tx_verify() {
    let mut alice = TrackedAccount::new();
    let mut bob = TrackedAccount::new();

    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    bob.set_balance(XELIS_ASSET, 0);

    // Alice account is cloned to not be updated as it is used for verification and need current state
    let tx = create_tx_for(alice.clone(), bob.address(), 50, None);

    let mut state = MockChainState::new();

    // Create the chain state
    {
        let mut balances = HashMap::new();
        for (asset, balance) in &alice.balances {
            balances.insert(asset.clone(), balance.ciphertext.clone().take_ciphertext().unwrap());
        }
        state.accounts.insert(alice.keypair.get_public_key().compress(), MockAccount {
            balances,
            nonce: alice.nonce,
        });
    }

    {
        let mut balances = HashMap::new();
        for (asset, balance) in &bob.balances {
            balances.insert(asset.clone(), balance.ciphertext.clone().take_ciphertext().unwrap());
        }
        state.accounts.insert(bob.keypair.get_public_key().compress(), MockAccount {
            balances,
            nonce: alice.nonce,
        });
    }

    let hash = tx.hash();
    tx.verify(&hash, &mut state, &NoZKPCache).await.unwrap();

    // Check Bob balance
    let balance = bob.keypair.decrypt_to_point(&state.accounts[&bob.keypair.get_public_key().compress()].balances[&XELIS_ASSET]);    
    assert_eq!(balance, Scalar::from(50u64) * (*G));

    // Check Alice balance
    let balance = alice.keypair.decrypt_to_point(&state.accounts[&alice.keypair.get_public_key().compress()].balances[&XELIS_ASSET]);
    assert_eq!(balance, Scalar::from((100u64 * COIN_VALUE) - (50 + tx.fee)) * (*G));
}

#[tokio::test]
async fn test_tx_verify_with_zkp_cache() {
    let mut alice = TrackedAccount::new();
    let mut bob = TrackedAccount::new();

    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    bob.set_balance(XELIS_ASSET, 0);

    // Alice account is cloned to not be updated as it is used for verification and need current state
    let tx = create_tx_for(alice.clone(), bob.address(), 50, None);

    let mut state = MockChainState::new();

    // Create the chain state
    {
        let mut balances = HashMap::new();
        for (asset, balance) in &alice.balances {
            balances.insert(asset.clone(), balance.ciphertext.clone().take_ciphertext().unwrap());
        }
        state.accounts.insert(alice.keypair.get_public_key().compress(), MockAccount {
            balances,
            nonce: alice.nonce,
        });
    }

    {
        let mut balances = HashMap::new();
        for (asset, balance) in &bob.balances {
            balances.insert(asset.clone(), balance.ciphertext.clone().take_ciphertext().unwrap());
        }
        state.accounts.insert(bob.keypair.get_public_key().compress(), MockAccount {
            balances,
            nonce: alice.nonce,
        });
    }

    let mut clean_state = state.clone();
    let hash = tx.hash();
    {
        // Ensure the TX is valid first
        assert!(tx.verify(&hash, &mut state, &NoZKPCache).await.is_ok());    
    }

    struct DummyCache;

    #[async_trait]
    impl<E> ZKPCache<E> for DummyCache {
        async fn is_already_verified(&self, _: &Hash) -> Result<bool, E> {
            Ok(true)
        }
    }

    // Fix the nonce to pass the verification
    state.accounts.get_mut(&alice.keypair.get_public_key().compress())
        .unwrap()
        .nonce = 0;

    // Now, the chain state balances has changed, it should error even if the TX is in cache
    assert!(matches!(tx.verify(&hash, &mut state, &DummyCache).await, Err(VerificationStateError::VerificationError(VerificationError::Proof(ProofVerificationError::GenericProof)))));

    // But should be fine for a clean state
    assert!(tx.verify(&hash, &mut clean_state, &DummyCache).await.is_ok());
}

#[tokio::test]
async fn test_burn_tx_verify() {
    let mut alice = TrackedAccount::new();
    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);

    let tx = {
        let mut state = AccountStateImpl {
            balances: alice.balances.clone(),
            nonce: alice.nonce,
            reference: Reference {
                topoheight: 0,
                hash: Hash::zero(),
            },
        };
    
        let data = TransactionTypeBuilder::Burn(BurnPayload {
            amount: 50 * COIN_VALUE,
            asset: XELIS_ASSET,
        });
        let builder = TransactionBuilder::new(TxVersion::V0, alice.keypair.get_public_key().compress(), None, data, FeeBuilder::default());
        let estimated_size = builder.estimate_size();
        let tx = builder.build(&mut state, &alice.keypair).unwrap();
        assert!(estimated_size == tx.size());
        assert!(tx.to_bytes().len() == estimated_size);

        Arc::new(tx)
    };

    let mut state = MockChainState::new();

    // Create the chain state
    {
        let mut balances = HashMap::new();
        for (asset, balance) in &alice.balances {
            balances.insert(asset.clone(), balance.ciphertext.clone().take_ciphertext().unwrap());
        }
        state.accounts.insert(alice.keypair.get_public_key().compress(), MockAccount {
            balances,
            nonce: alice.nonce,
        });
    }

    let hash = tx.hash();
    tx.verify(&hash, &mut state, &NoZKPCache).await.unwrap();

    // Check Alice balance
    let balance = alice.keypair.decrypt_to_point(&state.accounts[&alice.keypair.get_public_key().compress()].balances[&XELIS_ASSET]);
    assert_eq!(balance, Scalar::from((100u64 * COIN_VALUE) - (50 * COIN_VALUE + tx.fee)) * (*G));
}

#[tokio::test]
async fn test_tx_invoke_contract() {
    let mut alice = TrackedAccount::new();

    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);

    let tx = {
        let mut state = AccountStateImpl {
            balances: alice.balances.clone(),
            nonce: alice.nonce,
            reference: Reference {
                topoheight: 0,
                hash: Hash::zero(),
            },
        };

        let data = TransactionTypeBuilder::InvokeContract(InvokeContractBuilder {
            contract: Hash::zero(),
            entry_id: 0,
            max_gas: 1000,
            parameters: Vec::new(),
            deposits: [
                (XELIS_ASSET, ContractDepositBuilder {
                    amount: 50 * COIN_VALUE,
                    private: false
                })
            ].into_iter().collect(),
            permission: Default::default(),
        });
        let builder = TransactionBuilder::new(TxVersion::V2, alice.keypair.get_public_key().compress(), None, data, FeeBuilder::default());
        let estimated_size = builder.estimate_size();
        let tx = builder.build(&mut state, &alice.keypair).unwrap();
        assert!(estimated_size == tx.size(), "expected {} bytes got {} bytes", tx.size(), estimated_size);
        assert!(tx.to_bytes().len() == estimated_size);

        Arc::new(tx)
    };

    let mut state = MockChainState::new();
    let mut module = Module::new();
    module.add_entry_chunk(Chunk::new(), None);

    state.internal_set_contract_module(
        Hash::zero(),
        ContractModule {
            version: Default::default(),
            module: Arc::new(module)
        },
    );

    // Create the chain state
    {
        let mut balances = HashMap::new();
        for (asset, balance) in &alice.balances {
            balances.insert(asset.clone(), balance.ciphertext.clone().take_ciphertext().unwrap());
        }
        state.accounts.insert(alice.keypair.get_public_key().compress(), MockAccount {
            balances,
            nonce: alice.nonce,
        });
    }

    let hash = tx.hash();
    tx.verify(&hash, &mut state, &NoZKPCache).await.unwrap();

    // Check Alice balance
    let balance = alice.keypair.decrypt_to_point(&state.accounts[&alice.keypair.get_public_key().compress()].balances[&XELIS_ASSET]);
    // 50 coins deposit + tx fee + 1000 gas fee
    let total_spend = (50 * COIN_VALUE) + tx.fee + 1000;

    assert_eq!(balance, Scalar::from((100 * COIN_VALUE) - total_spend) * (*G));
}

#[tokio::test]
async fn test_tx_deploy_contract() {
    let mut alice = TrackedAccount::new();

    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);

    let max_gas = 500;
    let deposit = 10;

    let tx = {
        let mut state = AccountStateImpl {
            balances: alice.balances.clone(),
            nonce: alice.nonce,
            reference: Reference {
                topoheight: 0,
                hash: Hash::zero(),
            },
        };

        let mut module = Module::new();
        module.add_entry_chunk(Chunk::new(), None);

        // constructor
        module.add_hook_chunk(0, Chunk::new());

        assert!(module.size() == module.to_bytes().len());

        let data = TransactionTypeBuilder::DeployContract(DeployContractBuilder {
            contract_version: Default::default(),
            module: module.to_hex(),
            invoke: Some(DeployContractInvokeBuilder {
                deposits: [(XELIS_ASSET, ContractDepositBuilder {
                    amount: deposit,
                    private: false
                })].into(),
                max_gas,
            }),
        });
        let builder = TransactionBuilder::new(TxVersion::V2, alice.keypair.get_public_key().compress(), None, data, FeeBuilder::default());
        let estimated_size = builder.estimate_size();
        let tx = builder.build(&mut state, &alice.keypair).unwrap();
        assert!(tx.to_bytes().len() == tx.size(), "expected {} bytes but estimated {} bytes", tx.to_bytes().len(), tx.size());
        assert!(estimated_size == tx.size(), "expected {} bytes got {} bytes", tx.size(), estimated_size);

        Arc::new(tx)
    };

    let mut state = MockChainState::new();

    // Create the chain state
    {
        let mut balances = HashMap::new();
        for (asset, balance) in &alice.balances {
            balances.insert(asset.clone(), balance.ciphertext.clone().take_ciphertext().unwrap());
        }
        state.accounts.insert(alice.keypair.get_public_key().compress(), MockAccount {
            balances,
            nonce: alice.nonce,
        });
    }

    let hash = tx.hash();
    tx.verify(&hash, &mut state, &NoZKPCache).await.unwrap();

    // Check Alice balance
    let balance = alice.keypair.decrypt_to_point(&state.accounts[&alice.keypair.get_public_key().compress()].balances[&XELIS_ASSET]);
    // 1 XEL for contract deploy, tx fee, max gas + deposit
    let total_spend = BURN_PER_CONTRACT + tx.fee + max_gas + deposit;

    assert_eq!(balance, Scalar::from((100 * COIN_VALUE) - total_spend) * (*G));
}

#[tokio::test]
async fn test_max_transfers() {
    let mut alice = TrackedAccount::new();
    let mut bob = TrackedAccount::new();

    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    bob.set_balance(XELIS_ASSET, 0);

    let tx = {
        let mut transfers = Vec::new();
        for _ in 0..MAX_TRANSFER_COUNT {
            transfers.push(TransferBuilder {
                amount: 1,
                destination: bob.address(),
                asset: XELIS_ASSET,
                extra_data: None,
                encrypt_extra_data: true,
            });
        }

        let mut state = AccountStateImpl {
            balances: alice.balances.clone(),
            nonce: alice.nonce,
            reference: Reference {
                topoheight: 0,
                hash: Hash::zero(),
            },
        };

        let data = TransactionTypeBuilder::Transfers(transfers);
        let builder = TransactionBuilder::new(TxVersion::V0, alice.keypair.get_public_key().compress(), None, data, FeeBuilder::default());
        let estimated_size = builder.estimate_size();
        let tx = builder.build(&mut state, &alice.keypair).unwrap();
        assert!(estimated_size == tx.size());
        assert!(tx.to_bytes().len() == estimated_size);

        Arc::new(tx)
    };

    // Create the chain state
    let mut state = MockChainState::new();

    // Alice
    {
        let mut balances = HashMap::new();
        for (asset, balance) in alice.balances {
            balances.insert(asset, balance.ciphertext.take_ciphertext().unwrap());
        }
        state.accounts.insert(alice.keypair.get_public_key().compress(), MockAccount {
            balances,
            nonce: alice.nonce,
        });
    }

    // Bob
    {
        let mut balances = HashMap::new();
        for (asset, balance) in bob.balances {
            balances.insert(asset, balance.ciphertext.take_ciphertext().unwrap());
        }
        state.accounts.insert(bob.keypair.get_public_key().compress(), MockAccount {
            balances,
            nonce: alice.nonce,
        });
    }
    let hash = tx.hash();
    tx.verify(&hash, &mut state, &NoZKPCache).await.unwrap();
}

#[tokio::test]
async fn test_multisig_setup() {
    let mut alice = TrackedAccount::new();
    let mut bob = TrackedAccount::new();
    let charlie = TrackedAccount::new();

    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    bob.set_balance(XELIS_ASSET, 0);

    let tx = {
        let mut state = AccountStateImpl {
            balances: alice.balances.clone(),
            nonce: alice.nonce,
            reference: Reference {
                topoheight: 0,
                hash: Hash::zero(),
            },
        };
    
        let data = TransactionTypeBuilder::MultiSig(MultiSigBuilder {
            threshold: 2,
            participants: IndexSet::from_iter(vec![bob.keypair.get_public_key().to_address(false), charlie.keypair.get_public_key().to_address(false)]),
        });
        let builder = TransactionBuilder::new(TxVersion::V1, alice.keypair.get_public_key().compress(), None, data, FeeBuilder::default());
        let estimated_size = builder.estimate_size();
        let tx = builder.build(&mut state, &alice.keypair).unwrap();
        assert!(estimated_size == tx.size());
        assert!(tx.to_bytes().len() == estimated_size);

        Arc::new(tx)
    };

    let mut state = MockChainState::new();

    // Create the chain state
    {
        let mut balances = HashMap::new();
        for (asset, balance) in alice.balances {
            balances.insert(asset, balance.ciphertext.take_ciphertext().unwrap());
        }
        state.accounts.insert(alice.keypair.get_public_key().compress(), MockAccount {
            balances,
            nonce: alice.nonce,
        });
    }

    {
        let mut balances = HashMap::new();
        for (asset, balance) in bob.balances {
            balances.insert(asset, balance.ciphertext.take_ciphertext().unwrap());
        }
        state.accounts.insert(bob.keypair.get_public_key().compress(), MockAccount {
            balances,
            nonce: alice.nonce,
        });
    }

    let hash = tx.hash();
    tx.verify(&hash, &mut state, &NoZKPCache).await.unwrap();

    assert!(state.multisig.contains_key(&alice.keypair.get_public_key().compress()));
}

#[tokio::test]
async fn test_multisig() {
    let mut alice = TrackedAccount::new();
    let mut bob = TrackedAccount::new();

    // Signers
    let charlie = TrackedAccount::new();
    let dave = TrackedAccount::new();

    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    bob.set_balance(XELIS_ASSET, 0);

    let reference = Reference { topoheight: 0, hash: Hash::zero() };
    let tx = Arc::new(create_multisig_transfer_tx(
        &mut alice.clone(),
        bob.address(),
        1,
        &[(0, &charlie), (1, &dave)],
        TxVersion::V1,
        reference,
    ));

    // Create the chain state
    let mut state = MockChainState::new();

    // Alice: use pre-TX balances so the ZKP verifies against the original ciphertext
    {
        let mut balances = HashMap::new();
        for (asset, balance) in alice.balances {
            balances.insert(asset, balance.ciphertext.take_ciphertext().unwrap());
        }
        state.accounts.insert(alice.keypair.get_public_key().compress(), MockAccount {
            balances,
            nonce: alice.nonce,
        });
    }

    // Bob
    {
        let mut balances = HashMap::new();
        for (asset, balance) in bob.balances {
            balances.insert(asset, balance.ciphertext.take_ciphertext().unwrap());
        }

        state.accounts.insert(bob.keypair.get_public_key().compress(), MockAccount {
            balances,
            nonce: alice.nonce,
        });
    }

    state.multisig.insert(alice.keypair.get_public_key().compress(), MultiSigPayload {
        threshold: 2,
        participants: IndexSet::from_iter(vec![charlie.keypair.get_public_key().compress(), dave.keypair.get_public_key().compress()]),
    });

    let hash = tx.hash();
    tx.verify(&hash, &mut state, &NoZKPCache).await.unwrap();
}

/// A TX whose nonce doesn't match what the chain state expects must be rejected.
#[tokio::test]
async fn test_tx_invalid_nonce() {
    let mut alice = TrackedAccount::new();
    let mut bob = TrackedAccount::new();

    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    bob.set_balance(XELIS_ASSET, 0);

    // TX is built with nonce 0
    let tx = create_tx_for(alice.clone(), bob.address(), 50, None);

    let mut state = MockChainState::new();

    // Put nonce 1 in the chain state: the TX carries nonce 0, so it's stale
    {
        let mut balances = HashMap::new();
        for (asset, balance) in &alice.balances {
            balances.insert(asset.clone(), balance.ciphertext.clone().take_ciphertext().unwrap());
        }
        state.accounts.insert(alice.keypair.get_public_key().compress(), MockAccount {
            balances,
            nonce: 1,
        });
    }
    {
        let mut balances = HashMap::new();
        for (asset, balance) in &bob.balances {
            balances.insert(asset.clone(), balance.ciphertext.clone().take_ciphertext().unwrap());
        }
        state.accounts.insert(bob.keypair.get_public_key().compress(), MockAccount {
            balances,
            nonce: 0,
        });
    }

    let hash = tx.hash();
    let result = tx.verify(&hash, &mut state, &NoZKPCache).await;
    assert!(
        matches!(result, Err(VerificationStateError::VerificationError(VerificationError::InvalidNonce(..)))),
        "expected InvalidNonce, got: {:?}", result
    );
}

/// Replaying an already-applied TX must be rejected because the nonce was
/// incremented during the first successful verification.
#[tokio::test]
async fn test_tx_replay() {
    let mut alice = TrackedAccount::new();
    let mut bob = TrackedAccount::new();

    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    bob.set_balance(XELIS_ASSET, 0);

    let tx = create_tx_for(alice.clone(), bob.address(), 50, None);

    let mut state = MockChainState::new();
    {
        let mut balances = HashMap::new();
        for (asset, balance) in &alice.balances {
            balances.insert(asset.clone(), balance.ciphertext.clone().take_ciphertext().unwrap());
        }
        state.accounts.insert(alice.keypair.get_public_key().compress(), MockAccount {
            balances,
            nonce: alice.nonce,
        });
    }
    {
        let mut balances = HashMap::new();
        for (asset, balance) in &bob.balances {
            balances.insert(asset.clone(), balance.ciphertext.clone().take_ciphertext().unwrap());
        }
        state.accounts.insert(bob.keypair.get_public_key().compress(), MockAccount {
            balances,
            nonce: 0,
        });
    }

    let hash = tx.hash();

    // First application succeeds and advances Alice's on-chain nonce to 1
    tx.verify(&hash, &mut state, &NoZKPCache).await.unwrap();

    // Replaying the same TX now fails: on-chain nonce is 1, TX carries 0
    let result = tx.verify(&hash, &mut state, &NoZKPCache).await;
    assert!(
        matches!(result, Err(VerificationStateError::VerificationError(VerificationError::InvalidNonce(..)))),
        "expected InvalidNonce on replay, got: {:?}", result
    );
}

/// The builder must reject a transfer whose destination equals the sender.
#[test]
fn test_sender_is_receiver_rejected_at_build() {
    let mut alice = TrackedAccount::new();
    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);

    let mut state = AccountStateImpl {
        balances: alice.balances.clone(),
        nonce: alice.nonce,
        reference: Reference { topoheight: 0, hash: Hash::zero() },
    };

    let data = TransactionTypeBuilder::Transfers(vec![TransferBuilder {
        amount: 50,
        destination: alice.address(), // sender == receiver
        asset: XELIS_ASSET,
        extra_data: None,
        encrypt_extra_data: true,
    }]);

    let builder = TransactionBuilder::new(
        TxVersion::V0,
        alice.keypair.get_public_key().compress(),
        None,
        data,
        FeeBuilder::default(),
    );
    let result = builder.build(&mut state, &alice.keypair);
    assert!(
        matches!(result, Err(GenerationStateError::GenerationError(GenerationError::SenderIsReceiver))),
        "expected SenderIsReceiver, got: {:?}", result
    );
}

/// Invoking a contract that does not exist in the chain state must fail.
#[tokio::test]
async fn test_tx_invoke_unknown_contract() {
    let mut alice = TrackedAccount::new();
    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);

    let tx = {
        let mut state = AccountStateImpl {
            balances: alice.balances.clone(),
            nonce: alice.nonce,
            reference: Reference { topoheight: 0, hash: Hash::zero() },
        };

        let data = TransactionTypeBuilder::InvokeContract(InvokeContractBuilder {
            contract: Hash::zero(),
            entry_id: 0,
            max_gas: 1000,
            parameters: Vec::new(),
            deposits: Default::default(),
            permission: Default::default(),
        });
        let builder = TransactionBuilder::new(
            TxVersion::V2,
            alice.keypair.get_public_key().compress(),
            None,
            data,
            FeeBuilder::default(),
        );
        Arc::new(builder.build(&mut state, &alice.keypair).unwrap())
    };

    // Chain state has no contract registered
    let mut state = MockChainState::new();
    {
        let mut balances = HashMap::new();
        for (asset, balance) in &alice.balances {
            balances.insert(asset.clone(), balance.ciphertext.clone().take_ciphertext().unwrap());
        }
        state.accounts.insert(alice.keypair.get_public_key().compress(), MockAccount {
            balances,
            nonce: alice.nonce,
        });
    }

    let hash = tx.hash();
    let result = tx.verify(&hash, &mut state, &NoZKPCache).await;
    assert!(
        matches!(result, Err(VerificationStateError::VerificationError(VerificationError::ContractNotFound))),
        "expected ContractNotFound, got: {:?}", result
    );
}

/// When the chain state records a multisig requirement for an account, a
/// plain TX (no multisig block) submitted by that account must be rejected.
#[tokio::test]
async fn test_multisig_required_not_provided() {
    let mut alice = TrackedAccount::new();
    let mut bob = TrackedAccount::new();
    let charlie = TrackedAccount::new();
    let dave = TrackedAccount::new();

    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    bob.set_balance(XELIS_ASSET, 0);

    // Plain transfer, no multisig signature block
    let tx = create_tx_for(alice.clone(), bob.address(), 50, None);

    let mut state = MockChainState::new();
    {
        let mut balances = HashMap::new();
        for (asset, balance) in &alice.balances {
            balances.insert(asset.clone(), balance.ciphertext.clone().take_ciphertext().unwrap());
        }
        state.accounts.insert(alice.keypair.get_public_key().compress(), MockAccount {
            balances,
            nonce: alice.nonce,
        });
    }
    {
        let mut balances = HashMap::new();
        for (asset, balance) in &bob.balances {
            balances.insert(asset.clone(), balance.ciphertext.clone().take_ciphertext().unwrap());
        }
        state.accounts.insert(bob.keypair.get_public_key().compress(), MockAccount {
            balances,
            nonce: 0,
        });
    }

    // Alice's account requires 2-of-2 multisig approval
    state.multisig.insert(alice.keypair.get_public_key().compress(), MultiSigPayload {
        threshold: 2,
        participants: IndexSet::from_iter(vec![
            charlie.keypair.get_public_key().compress(),
            dave.keypair.get_public_key().compress(),
        ]),
    });

    let hash = tx.hash();
    let result = tx.verify(&hash, &mut state, &NoZKPCache).await;
    assert!(
        matches!(result, Err(VerificationStateError::VerificationError(VerificationError::MultiSigNotFound))),
        "expected MultiSigNotFound, got: {:?}", result
    );
}

/// Multisig signatures from a key that is not a registered participant must be
/// rejected even when the signature count matches the threshold.
#[tokio::test]
async fn test_multisig_wrong_signer() {
    let mut alice = TrackedAccount::new();
    let mut bob = TrackedAccount::new();
    let charlie = TrackedAccount::new(); // registered at index 0
    let dave = TrackedAccount::new();    // registered at index 1
    let eve = TrackedAccount::new();     // NOT registered

    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    bob.set_balance(XELIS_ASSET, 0);

    let reference = Reference { topoheight: 0, hash: Hash::zero() };
    // Sign with eve at index 0 (charlie's slot) and charlie at index 1 (dave's slot)
    // neither signature matches the expected key in the config
    let tx = Arc::new(create_multisig_transfer_tx(
        &mut alice.clone(),
        bob.address(),
        1,
        &[(0, &eve), (1, &charlie)],
        TxVersion::V1,
        reference,
    ));

    let mut state = MockChainState::new();
    {
        let mut balances = HashMap::new();
        for (asset, balance) in &alice.balances {
            balances.insert(asset.clone(), balance.ciphertext.clone().take_ciphertext().unwrap());
        }
        state.accounts.insert(alice.keypair.get_public_key().compress(), MockAccount {
            balances,
            nonce: alice.nonce,
        });
    }
    {
        let mut balances = HashMap::new();
        for (asset, balance) in &bob.balances {
            balances.insert(asset.clone(), balance.ciphertext.clone().take_ciphertext().unwrap());
        }
        state.accounts.insert(bob.keypair.get_public_key().compress(), MockAccount {
            balances,
            nonce: bob.nonce,
        });
    }

    // Config: charlie at index 0, dave at index 1
    state.multisig.insert(alice.keypair.get_public_key().compress(), MultiSigPayload {
        threshold: 2,
        participants: IndexSet::from_iter(vec![
            charlie.keypair.get_public_key().compress(),
            dave.keypair.get_public_key().compress(),
        ]),
    });

    let hash = tx.hash();
    let result = tx.verify(&hash, &mut state, &NoZKPCache).await;
    // eve's signature at index 0 is checked against charlie's key -> invalid
    assert!(
        matches!(result, Err(VerificationStateError::VerificationError(VerificationError::InvalidSignature))),
        "expected InvalidSignature, got: {:?}", result
    );
}

/// When a contract invocation TX is applied but the contract does not exist in
/// the chain state (simulating a failed/removed deployment), the fee_limit MUST
/// still be permanently deducted from the sender.  Gas is refunded because no
/// execution happened.  The nonce is consumed so the slot is gone.
#[tokio::test]
async fn test_apply_partial_fee_paid_on_missing_contract() {
    let mut alice = TrackedAccount::new();
    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);

    let max_gas = 1000u64;

    let tx = {
        let mut state = AccountStateImpl {
            balances: alice.balances.clone(),
            nonce: alice.nonce,
            reference: Reference { topoheight: 0, hash: Hash::zero() },
        };

        let data = TransactionTypeBuilder::InvokeContract(InvokeContractBuilder {
            contract: Hash::zero(),
            entry_id: 0,
            max_gas,
            parameters: Vec::new(),
            deposits: Default::default(), // no deposit to keep the assertion simple
            permission: Default::default(),
        });
        let builder = TransactionBuilder::new(
            TxVersion::V2,
            alice.keypair.get_public_key().compress(),
            None,
            data,
            FeeBuilder::default(),
        );
        Arc::new(builder.build(&mut state, &alice.keypair).unwrap())
    };

    // State has Alice's balance but the contract is NOT registered.
    let mut state = MockChainState::new();
    {
        let mut balances = HashMap::new();
        for (asset, balance) in &alice.balances {
            balances.insert(asset.clone(), balance.ciphertext.clone().take_ciphertext().unwrap());
        }
        state.accounts.insert(alice.keypair.get_public_key().compress(), MockAccount {
            balances,
            nonce: alice.nonce,
        });
    }

    let hash = tx.hash();
    tx.apply_with_partial_verify(&hash, &mut state).await.unwrap();

    // Nonce must be consumed even though the contract was not executed.
    assert_eq!(
        state.accounts[&alice.keypair.get_public_key().compress()].nonce,
        1,
        "nonce must be incremented to 1"
    );

    // No gas was actually executed so no gas fee should be tracked.
    assert_eq!(state.gas_fee, 0, "gas_fee must be 0 since no execution occurred");

    // Alice's balance must be reduced by exactly fee_limit.
    // The full max_gas is refunded (unused), no deposits to worry about.
    // The fee_limit is NOT refunded because apply_with_partial_verify does not
    // apply the fee-limit refund that verify_dynamic_parts would apply.
    let balance = alice.keypair.decrypt_to_point(
        &state.accounts[&alice.keypair.get_public_key().compress()].balances[&XELIS_ASSET],
    );
    let expected = (100 * COIN_VALUE) - tx.get_fee_limit();
    assert_eq!(
        balance,
        Scalar::from(expected) * (*G),
        "expected balance {} (paid fee_limit = {}), but got a different decrypted point",
        expected,
        tx.get_fee_limit()
    );
}

/// Extending the previous test: even when the failed contract invoke also
/// carried a public deposit, the deposit is refunded while the fee_limit is not.
#[tokio::test]
async fn test_apply_partial_deposit_refunded_fee_paid_on_missing_contract() {
    let mut alice = TrackedAccount::new();
    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);

    let max_gas = 1000u64;
    let deposit = 50 * COIN_VALUE;

    let tx = {
        let mut state = AccountStateImpl {
            balances: alice.balances.clone(),
            nonce: alice.nonce,
            reference: Reference { topoheight: 0, hash: Hash::zero() },
        };

        let data = TransactionTypeBuilder::InvokeContract(InvokeContractBuilder {
            contract: Hash::zero(),
            entry_id: 0,
            max_gas,
            parameters: Vec::new(),
            deposits: [(XELIS_ASSET, ContractDepositBuilder {
                amount: deposit,
                private: false,
            })].into_iter().collect(),
            permission: Default::default(),
        });
        let builder = TransactionBuilder::new(
            TxVersion::V2,
            alice.keypair.get_public_key().compress(),
            None,
            data,
            FeeBuilder::default(),
        );
        Arc::new(builder.build(&mut state, &alice.keypair).unwrap())
    };

    let mut state = MockChainState::new();
    {
        let mut balances = HashMap::new();
        for (asset, balance) in &alice.balances {
            balances.insert(asset.clone(), balance.ciphertext.clone().take_ciphertext().unwrap());
        }
        state.accounts.insert(alice.keypair.get_public_key().compress(), MockAccount {
            balances,
            nonce: alice.nonce,
        });
    }

    let hash = tx.hash();
    tx.apply_with_partial_verify(&hash, &mut state).await.unwrap();

    // Nonce consumed.
    assert_eq!(
        state.accounts[&alice.keypair.get_public_key().compress()].nonce,
        1,
    );

    // Gas fee is zero (no execution).
    assert_eq!(state.gas_fee, 0);

    // Deposit is refunded, max_gas is refunded, but fee_limit is permanently lost.
    // Net deduction = fee_limit only.
    let balance = alice.keypair.decrypt_to_point(
        &state.accounts[&alice.keypair.get_public_key().compress()].balances[&XELIS_ASSET],
    );
    let expected = (100 * COIN_VALUE) - tx.get_fee_limit();
    assert_eq!(
        balance,
        Scalar::from(expected) * (*G),
        "expected balance {} (deposit and gas refunded, fee_limit = {} kept), got a different point",
        expected,
        tx.get_fee_limit()
    );
}

/// Build a public blob TX (encrypt=false) with one destination and verify it.
/// A blob transfers no assets, so the sender only pays the fee.
#[tokio::test]
async fn test_blob_tx_public_build_verify() {
    let mut alice = TrackedAccount::new();
    let bob = TrackedAccount::new();

    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);

    let tx = {
        let mut state = AccountStateImpl {
            balances: alice.balances.clone(),
            nonce: alice.nonce,
            reference: Reference { topoheight: 0, hash: Hash::zero() },
        };

        let data = TransactionTypeBuilder::Blob(BlobPayloadBuilder {
            data: DataElement::Value(DataValue::String("hello public blob".to_string())),
            encrypt: false,
            destinations: vec![bob.address()],
        });
        let builder = TransactionBuilder::new(
            TxVersion::V3,
            alice.keypair.get_public_key().compress(),
            None,
            data,
            FeeBuilder::default(),
        );
        let estimated_size = builder.estimate_size();
        let tx = builder.build(&mut state, &alice.keypair).unwrap();
        assert_eq!(estimated_size, tx.size(), "estimated size mismatch");
        assert_eq!(tx.to_bytes().len(), tx.size());

        Arc::new(tx)
    };

    let mut state = MockChainState::new();
    {
        let mut balances = HashMap::new();
        for (asset, balance) in &alice.balances {
            balances.insert(asset.clone(), balance.ciphertext.clone().take_ciphertext().unwrap());
        }
        state.accounts.insert(alice.keypair.get_public_key().compress(), MockAccount {
            balances,
            nonce: alice.nonce,
        });
    }

    let hash = tx.hash();
    tx.verify(&hash, &mut state, &NoZKPCache).await.unwrap();

    // Blob sends no assets; Alice only pays the actual fee (fee_limit refund cancels the overhead).
    let balance = alice.keypair.decrypt_to_point(
        &state.accounts[&alice.keypair.get_public_key().compress()].balances[&XELIS_ASSET],
    );
    assert_eq!(balance, Scalar::from((100 * COIN_VALUE) - tx.fee) * (*G));
}

/// Build a private (encrypted) blob TX with one destination and verify it.
/// After verification, the destination can decrypt the embedded payload.
#[tokio::test]
async fn test_blob_tx_private_build_verify_and_decrypt() {
    let mut alice = TrackedAccount::new();
    let bob = TrackedAccount::new();

    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);

    let payload = DataElement::Value(DataValue::String("secret payload".to_string()));

    let tx = {
        let mut state = AccountStateImpl {
            balances: alice.balances.clone(),
            nonce: alice.nonce,
            reference: Reference { topoheight: 0, hash: Hash::zero() },
        };

        let data = TransactionTypeBuilder::Blob(BlobPayloadBuilder {
            data: payload.clone(),
            encrypt: true,
            destinations: vec![bob.address()],
        });
        let builder = TransactionBuilder::new(
            TxVersion::V3,
            alice.keypair.get_public_key().compress(),
            None,
            data,
            FeeBuilder::default(),
        );
        let estimated_size = builder.estimate_size();
        let tx = builder.build(&mut state, &alice.keypair).unwrap();
        assert_eq!(estimated_size, tx.size(), "estimated size mismatch");
        assert_eq!(tx.to_bytes().len(), tx.size());

        Arc::new(tx)
    };

    let mut state = MockChainState::new();
    {
        let mut balances = HashMap::new();
        for (asset, balance) in &alice.balances {
            balances.insert(asset.clone(), balance.ciphertext.clone().take_ciphertext().unwrap());
        }
        state.accounts.insert(alice.keypair.get_public_key().compress(), MockAccount {
            balances,
            nonce: alice.nonce,
        });
    }

    let hash = tx.hash();
    tx.verify(&hash, &mut state, &NoZKPCache).await.unwrap();

    // Blob sends no assets; Alice only pays the fee.
    let balance = alice.keypair.decrypt_to_point(
        &state.accounts[&alice.keypair.get_public_key().compress()].balances[&XELIS_ASSET],
    );
    assert_eq!(balance, Scalar::from((100 * COIN_VALUE) - tx.fee) * (*G));

    // Bob (the destination) can decrypt the blob data.
    let TransactionType::Blob(blob) = tx.get_data() else { unreachable!() };
    let decrypted = blob.get_data()
        .decrypt(&bob.keypair.get_private_key(), None, Role::Receiver, TxVersion::V3)
        .unwrap();
    assert_eq!(decrypted.data(), Some(&payload));
}

/// A public blob can have multiple destinations. Build and verify succeeds.
#[tokio::test]
async fn test_blob_tx_public_multiple_destinations_build_verify() {
    let mut alice = TrackedAccount::new();
    let bob = TrackedAccount::new();
    let charlie = TrackedAccount::new();
    let dave = TrackedAccount::new();

    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);

    let tx = {
        let mut state = AccountStateImpl {
            balances: alice.balances.clone(),
            nonce: alice.nonce,
            reference: Reference { topoheight: 0, hash: Hash::zero() },
        };

        let data = TransactionTypeBuilder::Blob(BlobPayloadBuilder {
            data: DataElement::Value(DataValue::String("broadcast blob".to_string())),
            encrypt: false,
            destinations: vec![bob.address(), charlie.address(), dave.address()],
        });
        let builder = TransactionBuilder::new(
            TxVersion::V3,
            alice.keypair.get_public_key().compress(),
            None,
            data,
            FeeBuilder::default(),
        );
        let estimated_size = builder.estimate_size();
        let tx = builder.build(&mut state, &alice.keypair).unwrap();
        assert_eq!(estimated_size, tx.size(), "estimated size mismatch");
        assert_eq!(tx.to_bytes().len(), tx.size());

        Arc::new(tx)
    };

    let mut state = MockChainState::new();
    {
        let mut balances = HashMap::new();
        for (asset, balance) in &alice.balances {
            balances.insert(asset.clone(), balance.ciphertext.clone().take_ciphertext().unwrap());
        }
        state.accounts.insert(alice.keypair.get_public_key().compress(), MockAccount {
            balances,
            nonce: alice.nonce,
        });
    }

    let hash = tx.hash();
    tx.verify(&hash, &mut state, &NoZKPCache).await.unwrap();

    let TransactionType::Blob(blob) = tx.get_data() else { unreachable!() };
    assert_eq!(blob.get_destinations().len(), 3);
}

/// An encrypted blob with more than one destination is rejected at build time
/// because the encrypted data can only be addressed to a single receiver.
#[test]
fn test_blob_tx_private_multiple_destinations_rejected_at_build() {
    let mut alice = TrackedAccount::new();
    let bob = TrackedAccount::new();
    let charlie = TrackedAccount::new();

    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);

    let mut state = AccountStateImpl {
        balances: alice.balances.clone(),
        nonce: alice.nonce,
        reference: Reference { topoheight: 0, hash: Hash::zero() },
    };

    let data = TransactionTypeBuilder::Blob(BlobPayloadBuilder {
        data: DataElement::Value(DataValue::String("too many receivers".to_string())),
        encrypt: true,
        destinations: vec![bob.address(), charlie.address()],
    });
    let builder = TransactionBuilder::new(
        TxVersion::V3,
        alice.keypair.get_public_key().compress(),
        None,
        data,
        FeeBuilder::default(),
    );
    let result = builder.build(&mut state, &alice.keypair);
    assert!(
        matches!(result, Err(GenerationStateError::GenerationError(GenerationError::ExpectedOneDestinationForBlob(2)))),
        "expected ExpectedOneDestinationForBlob(2), got: {:?}", result
    );
}

/// A blob TX where the sender is listed as a destination is rejected at build time.
#[test]
fn test_blob_tx_sender_is_destination_rejected_at_build() {
    let mut alice = TrackedAccount::new();

    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);

    let mut state = AccountStateImpl {
        balances: alice.balances.clone(),
        nonce: alice.nonce,
        reference: Reference { topoheight: 0, hash: Hash::zero() },
    };

    let data = TransactionTypeBuilder::Blob(BlobPayloadBuilder {
        data: DataElement::Value(DataValue::String("self-addressed blob".to_string())),
        encrypt: false,
        destinations: vec![alice.address()],
    });
    let builder = TransactionBuilder::new(
        TxVersion::V3,
        alice.keypair.get_public_key().compress(),
        None,
        data,
        FeeBuilder::default(),
    );
    let result = builder.build(&mut state, &alice.keypair);
    assert!(
        matches!(result, Err(GenerationStateError::GenerationError(GenerationError::SenderIsReceiver))),
        "expected SenderIsReceiver, got: {:?}", result
    );
}

/// A blob TX must have at least one destination.
#[test]
fn test_blob_tx_empty_destinations_rejected_at_build() {
    let mut alice = TrackedAccount::new();

    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);

    let mut state = AccountStateImpl {
        balances: alice.balances.clone(),
        nonce: alice.nonce,
        reference: Reference { topoheight: 0, hash: Hash::zero() },
    };

    let data = TransactionTypeBuilder::Blob(BlobPayloadBuilder {
        data: DataElement::Value(DataValue::String("empty destinations".to_string())),
        encrypt: false,
        destinations: vec![],
    });
    let builder = TransactionBuilder::new(
        TxVersion::V3,
        alice.keypair.get_public_key().compress(),
        None,
        data,
        FeeBuilder::default(),
    );
    let result = builder.build(&mut state, &alice.keypair);
    assert!(
        matches!(result, Err(GenerationStateError::GenerationError(GenerationError::BlobMissingDestination))),
        "expected BlobMissingDestination, got: {:?}", result
    );
}

/// Consensus verification also rejects manually crafted blob TXs without destinations.
#[tokio::test]
async fn test_blob_tx_empty_destinations_rejected_at_verify() {
    let mut alice = TrackedAccount::new();
    let bob = TrackedAccount::new();

    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);

    let tx = {
        let mut state = AccountStateImpl {
            balances: alice.balances.clone(),
            nonce: alice.nonce,
            reference: Reference { topoheight: 0, hash: Hash::zero() },
        };

        let data = TransactionTypeBuilder::Blob(BlobPayloadBuilder {
            data: DataElement::Value(DataValue::String("empty destinations".to_string())),
            encrypt: false,
            destinations: vec![bob.address()],
        });
        let builder = TransactionBuilder::new(
            TxVersion::V3,
            alice.keypair.get_public_key().compress(),
            None,
            data,
            FeeBuilder::default(),
        );
        let tx = builder.build(&mut state, &alice.keypair).unwrap();
        let TransactionType::Blob(blob) = tx.get_data().clone() else { unreachable!() };
        Arc::new(Transaction::new(
            tx.get_version(),
            tx.get_source().clone(),
            TransactionType::Blob(BlobPayload {
                data: blob.data,
                destinations: IndexSet::new(),
            }),
            tx.get_fee(),
            tx.get_fee_limit(),
            tx.get_nonce(),
            tx.get_source_commitments().clone(),
            tx.get_range_proof().clone(),
            tx.get_reference().clone(),
            tx.get_multisig().clone(),
            tx.get_signature().clone(),
        ))
    };

    let mut state = MockChainState::new();
    {
        let mut balances = HashMap::new();
        for (asset, balance) in &alice.balances {
            balances.insert(asset.clone(), balance.ciphertext.clone().take_ciphertext().unwrap());
        }
        state.accounts.insert(alice.keypair.get_public_key().compress(), MockAccount {
            balances,
            nonce: alice.nonce,
        });
    }

    let hash = tx.hash();
    let result = tx.verify(&hash, &mut state, &NoZKPCache).await;
    assert!(
        matches!(result, Err(VerificationStateError::VerificationError(VerificationError::InvalidFormat))),
        "expected InvalidFormat for empty blob destinations, got: {:?}", result
    );
}

/// A blob TX built with a version earlier than V3 must be rejected at verification
/// because blobs are only supported since V3.
#[tokio::test]
async fn test_blob_tx_wrong_version_rejected_at_verify() {
    let mut alice = TrackedAccount::new();
    let bob = TrackedAccount::new();

    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);

    // Build with V2 (blobs require >= V3); the builder accepts it but verify rejects it.
    let tx = {
        let mut state = AccountStateImpl {
            balances: alice.balances.clone(),
            nonce: alice.nonce,
            reference: Reference { topoheight: 0, hash: Hash::zero() },
        };

        let data = TransactionTypeBuilder::Blob(BlobPayloadBuilder {
            data: DataElement::Value(DataValue::String("versioned blob".to_string())),
            encrypt: false,
            destinations: vec![bob.address()],
        });
        let builder = TransactionBuilder::new(
            TxVersion::V2,
            alice.keypair.get_public_key().compress(),
            None,
            data,
            FeeBuilder::default(),
        );
        Arc::new(builder.build(&mut state, &alice.keypair).unwrap())
    };

    // has_valid_version_format() returns false for a V2 blob, which triggers InvalidFormat.
    assert!(!tx.has_valid_version_format());

    let mut state = MockChainState::new();
    {
        let mut balances = HashMap::new();
        for (asset, balance) in &alice.balances {
            balances.insert(asset.clone(), balance.ciphertext.clone().take_ciphertext().unwrap());
        }
        state.accounts.insert(alice.keypair.get_public_key().compress(), MockAccount {
            balances,
            nonce: alice.nonce,
        });
    }

    let hash = tx.hash();
    let result = tx.verify(&hash, &mut state, &NoZKPCache).await;
    assert!(
        matches!(result, Err(VerificationStateError::VerificationError(VerificationError::InvalidFormat))),
        "expected InvalidFormat for V2 blob, got: {:?}", result
    );
}

impl FeeHelper for AccountStateImpl {
    type Error = anyhow::Error;

    fn get_max_fee(&self, fee: u64) -> u64 {
        fee * 2
    }

    fn account_exists(&self, _: &PublicKey) -> Result<bool, Self::Error> {
        Ok(false)
    }
}

impl AccountState for AccountStateImpl {
    fn is_mainnet(&self) -> bool {
        false
    }

    fn get_account_balance(&self, asset: &Hash) -> Result<u64, Self::Error> {
        self.balances.get(asset)
            .map(|balance| balance.balance)
            .context("account balance not found")
    }

    fn get_account_ciphertext(&self, asset: &Hash) -> Result<CiphertextCache, Self::Error> {
        self.balances.get(asset)
            .map(|balance| balance.ciphertext.clone())
            .context("account ciphertext not found")
    }

    fn get_reference(&self) -> Reference {
        self.reference.clone()
    }

    fn update_account_balance(&mut self, asset: &Hash, balance: u64, ciphertext: Ciphertext) -> Result<(), Self::Error> {
        self.balances.insert(asset.clone(), TrackedBalance {
            balance,
            ciphertext: CiphertextCache::Decompressed(None, ciphertext),
        });
        Ok(())
    }

    fn get_nonce(&self) -> Result<Nonce, Self::Error> {
        Ok(self.nonce)
    }

    fn update_nonce(&mut self, new_nonce: Nonce) -> Result<(), Self::Error> {
        self.nonce = new_nonce;
        Ok(())
    }
}
