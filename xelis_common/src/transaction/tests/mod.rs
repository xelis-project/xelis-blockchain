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
            ContractDepositBuilder,
            DeployContractBuilder,
            DeployContractInvokeBuilder,
            FeeBuilder,
            FeeHelper,
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

    let tx = {
        let mut state = AccountStateImpl {
            balances: alice.balances.clone(),
            nonce: alice.nonce,
            reference: Reference {
                topoheight: 0,
                hash: Hash::zero(),
            },
        };
    
        let data = TransactionTypeBuilder::Transfers(vec![TransferBuilder {
            amount: 1,
            destination: bob.address(),
            asset: XELIS_ASSET,
            extra_data: None,
            encrypt_extra_data: true,
        }]);
        let builder = TransactionBuilder::new(TxVersion::V1, alice.keypair.get_public_key().compress(), Some(2), data, FeeBuilder::default());
        let mut tx = builder.build_unsigned(&mut state, &alice.keypair).unwrap();

        tx.sign_multisig(&charlie.keypair, 0);
        tx.sign_multisig(&dave.keypair, 1);

        Arc::new(tx.finalize(&alice.keypair))
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

    state.multisig.insert(alice.keypair.get_public_key().compress(), MultiSigPayload {
        threshold: 2,
        participants: IndexSet::from_iter(vec![charlie.keypair.get_public_key().compress(), dave.keypair.get_public_key().compress()]),
    });

    let hash = tx.hash();
    tx.verify(&hash, &mut state, &NoZKPCache).await.unwrap();
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