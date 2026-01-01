use std::{borrow::Cow, collections::HashMap, collections::hash_map::Entry, sync::Arc};
use async_trait::async_trait;
use curve25519_dalek::{ristretto::CompressedRistretto, traits::Identity, Scalar};
use indexmap::{IndexMap, IndexSet};
use xelis_builder::EnvironmentBuilder;
use xelis_vm::{Chunk, Environment, Module};
use crate::{
    account::{CiphertextCache, Nonce},
    api::{DataElement, DataValue},
    block::{Block, BlockHeader, BlockVersion, EXTRA_NONCE_SIZE},
    config::{BURN_PER_CONTRACT, COIN_VALUE, XELIS_ASSET},
    contract::{
        AssetChanges,
        ChainState as ContractChainState,
        ExecutionsManager,
        ExecutionsChanges,
        ContractCache,
        ContractEventTracker,
        ContractLog,
        ContractMetadata,
        ContractModule,
        ContractVersion,
        InterContractPermission,
        build_environment,
        tests::MockProvider,
        vm::ContractCaller
    },
    crypto::{
        elgamal::{Ciphertext, CompressedPublicKey, PedersenOpening},
        proofs::{G, ProofVerificationError},
        Address,
        Hash,
        Hashable,
        KeyPair,
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
        verify::{BlockchainApplyState, BlockchainContractState, BlockchainVerificationState, ContractEnvironment, NoZKPCache, VerificationError, ZKPCache},
        BurnPayload,
        ContractDeposit,
        MultiSigPayload,
        Reference,
        Role,
        Transaction,
        TransactionType,
        TxVersion,
        MAX_TRANSFER_COUNT
    },
    versioned_type::VersionedState
};

#[derive(Debug, Clone)]
pub struct AccountChainState {
    pub balances: HashMap<Hash, Ciphertext>,
    pub nonce: Nonce,
}

#[derive(Debug, Clone)]
pub struct MockChainState {
    pub accounts: HashMap<PublicKey, AccountChainState>,
    pub multisig: HashMap<PublicKey, MultiSigPayload>,
    pub contracts: HashMap<Hash, ContractModule>,
    pub contract_balances: HashMap<Hash, HashMap<Hash, (VersionedState, u64)>>,
    pub contract_logs: HashMap<Hash, Vec<ContractLog>>,
    pub burned_coins: HashMap<Hash, u64>,
    pub gas_fee: u64,
    pub burned_fee: u64,
    pub env: Arc<EnvironmentBuilder<'static, ContractMetadata>>,
    pub provider: MockProvider,
    pub mainnet: bool,
    pub block_hash: Hash,
    pub block: Block,
    pub global_caches: HashMap<Hash, ContractCache>,
    pub executions: ExecutionsChanges,
}

impl MockChainState {
    pub fn new() -> Self {
        let header = BlockHeader::new(
            BlockVersion::V3,
            0,
            0,
            IndexSet::new(),
            [0u8; EXTRA_NONCE_SIZE],
            CompressedPublicKey::new(CompressedRistretto::identity()),
            IndexSet::new(),
        );

        Self {
            accounts: HashMap::new(),
            multisig: HashMap::new(),
            contracts: HashMap::new(),
            contract_balances: HashMap::new(),
            contract_logs: HashMap::new(),
            burned_coins: HashMap::new(),
            gas_fee: 0,
            burned_fee: 0,
            env: Arc::new(build_environment::<MockProvider>(ContractVersion::V1)),
            provider: MockProvider::default(),
            mainnet: false,
            block_hash: Hash::zero(),
            block: Block::new(header, Vec::new()),
            global_caches: HashMap::new(),
            executions: ExecutionsChanges::default(),
        }
    }

    pub fn set_contract_balance(&mut self, contract: &Hash, asset: &Hash, new_balance: u64) {
        let balances = self.contract_balances.entry(contract.clone())
            .or_insert_with(HashMap::new);

        match balances.entry(asset.clone()) {
            Entry::Occupied(mut o) => {
                let (state, balance) = o.get_mut();
                *balance = new_balance;
                state.mark_updated();
            }
            Entry::Vacant(v) => {
                v.insert((VersionedState::New, new_balance));
            }
        }
    }

    pub fn get_contract_balance(&self, contract: &Hash, asset: &Hash) -> u64 {
        self.contract_balances.get(contract)
            .and_then(|balances| balances.get(asset))
            .map(|(_, balance)| *balance)
            .unwrap_or_default()
    }

    pub fn set_account_balance(&mut self, account: &PublicKey, asset: &Hash, balance: Ciphertext) {
        let acct_state = self.accounts.entry(account.clone())
            .or_insert_with(|| AccountChainState {
                balances: HashMap::new(),
                nonce: 0,
            });

        acct_state.balances.insert(asset.clone(), balance);
    }

    pub fn get_account_balance(&self, account: &PublicKey, asset: &Hash) -> Ciphertext {
        self.accounts.get(account)
            .and_then(|state| state.balances.get(asset))
            .cloned()
            .unwrap_or_else(|| Ciphertext::zero())
    }
}

#[derive(Clone)]
pub struct Balance {
    pub ciphertext: CiphertextCache,
    pub balance: u64,
}

#[derive(Clone)]
pub struct Account {
    pub balances: HashMap<Hash, Balance>,
    pub keypair: KeyPair,
    pub nonce: Nonce,
}

impl Account {
    pub fn new() -> Self {
        Self {
            balances: HashMap::new(),
            keypair: KeyPair::new(),
            nonce: 0,
        }
    }

    pub fn set_balance(&mut self, asset: Hash, balance: u64) {
        let ciphertext = self.keypair.get_public_key().encrypt(balance);
        self.balances.insert(asset, Balance {
            balance,
            ciphertext: CiphertextCache::Decompressed(None, ciphertext),
        });
    }

    pub fn address(&self) -> Address {
        self.keypair.get_public_key().to_address(false)
    }
}

pub struct AccountStateImpl {
    pub balances: HashMap<Hash, Balance>,
    pub reference: Reference,
    pub nonce: Nonce,
}

fn create_tx_for(account: Account, destination: Address, amount: u64, extra_data: Option<DataElement>) -> Arc<Transaction> {
    let mut state = AccountStateImpl {
        balances: account.balances,
        nonce: account.nonce,
        reference: Reference {
            topoheight: 0,
            hash: Hash::zero(),
        },
    };

    let data = TransactionTypeBuilder::Transfers(vec![TransferBuilder {
        amount,
        destination,
        asset: XELIS_ASSET,
        extra_data,
        encrypt_extra_data: true,
    }]);


    let balance = state.balances[&XELIS_ASSET].balance;
    let builder = TransactionBuilder::new(TxVersion::V1, account.keypair.get_public_key().compress(), None, data, FeeBuilder::default());
    let estimated_size = builder.estimate_size();
    let tx = builder.build(&mut state, &account.keypair).unwrap();
    assert!(estimated_size == tx.size(), "expected {} bytes got {} bytes", tx.size(), estimated_size);
    assert!(tx.to_bytes().len() == estimated_size);
    // this is done by the AccountStateImpl
    assert!(tx.fee * 2 == tx.fee_limit);

    let total_spend = amount + tx.fee_limit;
    let new_balance = state.balances[&XELIS_ASSET].balance;
    let expected_balance = balance - total_spend;
    assert!(new_balance == expected_balance, "expected balance {} got {}", expected_balance, new_balance);

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
    let mut alice = Account::new();
    alice.balances.insert(XELIS_ASSET, Balance {
        balance: 100 * COIN_VALUE,
        ciphertext: CiphertextCache::Decompressed(None, alice.keypair.get_public_key().encrypt(100 * COIN_VALUE)),
    });

    let bob = Account::new();

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
    let mut alice = Account::new();
    let mut bob = Account::new();

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
        state.accounts.insert(alice.keypair.get_public_key().compress(), AccountChainState {
            balances,
            nonce: alice.nonce,
        });
    }

    {
        let mut balances = HashMap::new();
        for (asset, balance) in &bob.balances {
            balances.insert(asset.clone(), balance.ciphertext.clone().take_ciphertext().unwrap());
        }
        state.accounts.insert(bob.keypair.get_public_key().compress(), AccountChainState {
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
    let mut alice = Account::new();
    let mut bob = Account::new();

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
        state.accounts.insert(alice.keypair.get_public_key().compress(), AccountChainState {
            balances,
            nonce: alice.nonce,
        });
    }

    {
        let mut balances = HashMap::new();
        for (asset, balance) in &bob.balances {
            balances.insert(asset.clone(), balance.ciphertext.clone().take_ciphertext().unwrap());
        }
        state.accounts.insert(bob.keypair.get_public_key().compress(), AccountChainState {
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
    assert!(matches!(tx.verify(&hash, &mut state, &DummyCache).await, Err(VerificationError::Proof(ProofVerificationError::GenericProof))));

    // But should be fine for a clean state
    assert!(tx.verify(&hash, &mut clean_state, &DummyCache).await.is_ok());
}

#[tokio::test]
async fn test_burn_tx_verify() {
    let mut alice = Account::new();
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
        state.accounts.insert(alice.keypair.get_public_key().compress(), AccountChainState {
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
    let mut alice = Account::new();

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
    module.add_entry_chunk(Chunk::new());
    state.contracts.insert(Hash::zero(), ContractModule { version: Default::default(), module: Arc::new(module) });

    // Create the chain state
    {
        let mut balances = HashMap::new();
        for (asset, balance) in &alice.balances {
            balances.insert(asset.clone(), balance.ciphertext.clone().take_ciphertext().unwrap());
        }
        state.accounts.insert(alice.keypair.get_public_key().compress(), AccountChainState {
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
    let mut alice = Account::new();

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
        module.add_entry_chunk(Chunk::new());

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
        state.accounts.insert(alice.keypair.get_public_key().compress(), AccountChainState {
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
    let mut alice = Account::new();
    let mut bob = Account::new();

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
        state.accounts.insert(alice.keypair.get_public_key().compress(), AccountChainState {
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
        state.accounts.insert(bob.keypair.get_public_key().compress(), AccountChainState {
            balances,
            nonce: alice.nonce,
        });
    }
    let hash = tx.hash();
    tx.verify(&hash, &mut state, &NoZKPCache).await.unwrap();
}

#[tokio::test]
async fn test_multisig_setup() {
    let mut alice = Account::new();
    let mut bob = Account::new();
    let charlie = Account::new();

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
        state.accounts.insert(alice.keypair.get_public_key().compress(), AccountChainState {
            balances,
            nonce: alice.nonce,
        });
    }

    {
        let mut balances = HashMap::new();
        for (asset, balance) in bob.balances {
            balances.insert(asset, balance.ciphertext.take_ciphertext().unwrap());
        }
        state.accounts.insert(bob.keypair.get_public_key().compress(), AccountChainState {
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
    let mut alice = Account::new();
    let mut bob = Account::new();

    // Signers
    let charlie = Account::new();
    let dave = Account::new();

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
        state.accounts.insert(alice.keypair.get_public_key().compress(), AccountChainState {
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

        state.accounts.insert(bob.keypair.get_public_key().compress(), AccountChainState {
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

#[async_trait]
impl<'a> BlockchainVerificationState<'a, ()> for MockChainState {
    /// Left over fee to pay back
    async fn handle_tx_fee<'b>(&'b mut self, tx: &Transaction, _: &Hash) -> Result<u64, ()> {
        Ok(tx.get_fee_limit() - tx.get_fee())
    }

    /// Pre-verify the TX
    async fn pre_verify_tx<'b>(
        &'b mut self,
        _: &Transaction,
    ) -> Result<(), ()> {
        Ok(())
    }

    /// Get the balance ciphertext for a receiver account
    async fn get_receiver_balance<'b>(
        &'b mut self,
        account: Cow<'a, PublicKey>,
        asset: Cow<'a, Hash>,
    ) -> Result<&'b mut Ciphertext, ()> {
        self.accounts.get_mut(&account).and_then(|account| account.balances.get_mut(&asset)).ok_or(())
    }

    /// Get the balance ciphertext used for verification of funds for the sender account
    async fn get_sender_balance<'b>(
        &'b mut self,
        account: &'a PublicKey,
        asset: &'a Hash,
        _: &Reference,
    ) -> Result<&'b mut Ciphertext, ()> {
        self.accounts.get_mut(account).and_then(|account| account.balances.get_mut(asset)).ok_or(())
    }

    /// Apply new output to a sender account
    async fn add_sender_output(
        &mut self,
        _: &'a PublicKey,
        _: &'a Hash,
        _: Ciphertext,
    ) -> Result<(), ()> {
        Ok(())
    }

    /// Get the nonce of an account
    async fn get_account_nonce(
        &mut self,
        account: &'a PublicKey
    ) -> Result<Nonce, ()> {
        self.accounts.get(account).map(|account| account.nonce).ok_or(())
    }

    /// Apply a new nonce to an account
    async fn update_account_nonce(
        &mut self,
        account: &'a PublicKey,
        new_nonce: Nonce
    ) -> Result<(), ()> {
        self.accounts.get_mut(account).map(|account| account.nonce = new_nonce).ok_or(())
    }

    fn get_block_version(&self) -> BlockVersion {
        BlockVersion::V0
    }

    async fn set_multisig_state(
        &mut self,
        account: &'a PublicKey,
        multisig: &MultiSigPayload
    ) -> Result<(), ()> {
        self.multisig.insert(account.clone(), multisig.clone());
        Ok(())
    }

    async fn get_multisig_state(
        &mut self,
        account: &'a PublicKey
    ) -> Result<Option<&MultiSigPayload>, ()> {
        Ok(self.multisig.get(account))
    }

    async fn get_environment(&mut self, _: ContractVersion) -> Result<&Environment<ContractMetadata>, ()> {
        Ok(self.env.environment())
    }

    async fn set_contract_module(
        &mut self,
        hash: &'a Hash,
        module: &'a ContractModule,
    ) -> Result<(), ()> {
        self.contracts.insert(hash.clone(), module.clone());
        Ok(())
    }

    async fn load_contract_module(
        &mut self,
        hash: Cow<'a, Hash>
    ) -> Result<bool, ()> {
        Ok(self.contracts.contains_key(&hash))
    }

    async fn get_contract_module_with_environment(
        &self,
        contract: &'a Hash
    ) -> Result<(&Module, &Environment<ContractMetadata>), ()> {
        let module = self.contracts.get(contract).ok_or(())?;
        Ok((&module.module, self.env.environment()))
    }
}

#[async_trait]
impl<'a> BlockchainContractState<'a, MockProvider, ()> for MockChainState {
    async fn set_contract_logs(
        &mut self,
        caller: ContractCaller<'a>,
        logs: Vec<ContractLog>,
    ) -> Result<(), ()> {
        let hash = caller.get_hash().into_owned();
        self.contract_logs.insert(hash, logs);
        Ok(())
    }

    async fn get_contract_environment_for<'b>(
        &'b mut self,
        contract: Cow<'b, Hash>,
        deposits: Option<&'b IndexMap<Hash, ContractDeposit>>,
        caller: ContractCaller<'b>,
        permission: Cow<'b, InterContractPermission>,
    ) -> Result<(ContractEnvironment<'b, MockProvider>, crate::contract::ChainState<'b>), ()> {
        // Get the contract module
        let contract_module = self.contracts.get(&contract).ok_or(())?;
        
        // Find the contract cache in our cache map
        let mut cache = self.global_caches.get(&contract)
            .cloned()
            .unwrap_or_default();

        // We need to add the deposits to the balances
        if let Some(deposits) = deposits {
            for (asset, deposit) in deposits.iter() {
                match deposit {
                    ContractDeposit::Public(amount) => match cache.balances.entry(asset.clone()) {
                        Entry::Occupied(mut o) => match o.get_mut() {
                            Some((state, balance)) => {
                                state.mark_updated();
                                *balance += amount;
                            },
                            None => {
                                // Balance was already fetched and we didn't had any balance before
                                o.insert(Some((VersionedState::New, *amount)));
                            }
                        },
                        Entry::Vacant(e) => {
                            // In tests, we don't have storage, so we start with 0 balance
                            e.insert(Some((VersionedState::New, *amount)));
                        }
                    },
                    ContractDeposit::Private { .. } => {
                        // TODO: we need to add the private deposit to the balance
                    }
                }
            }
        }
        
        // Create the contract environment
        let environment = ContractEnvironment {
            environment: &self.env.environment(),
            module: &contract_module.module,
            version: contract_module.version,
            provider: &self.provider,
        };

        // Create the chain state using stored references
        let chain_state = ContractChainState {
            debug_mode: false,
            mainnet: self.mainnet,
            // We only provide the current contract cache available
            // others can be lazily added to it
            caches: [(contract.as_ref().clone(), cache)].into_iter().collect(),
            entry_contract: contract,
            topoheight: 1,
            block_hash: &self.block_hash,
            block: &self.block,
            caller,
            outputs: Vec::new(),
            tracker: ContractEventTracker::default(),
            // Global caches (all contracts)
            global_caches: &mut self.global_caches,
            assets: HashMap::new(),
            modules: HashMap::new(),
            injected_gas: indexmap::IndexMap::new(),
            executions: ExecutionsManager {
                allow_executions: true,
                global_executions: &self.executions.executions,
                changes: Default::default(),
            },
            permission,
            gas_fee: 0,
            gas_fee_allowance: 0,
            environments: Cow::Owned(HashMap::new()),
        };

        Ok((environment, chain_state))
    }

    async fn set_modules_cache(
        &mut self,
        _modules: HashMap<Hash, Option<ContractModule>>,
    ) -> Result<(), ()> {
        // In tests, we don't need to track module cache updates
        Ok(())
    }

    async fn merge_contract_changes(
        &mut self,
        _caches: HashMap<Hash, ContractCache>,
        _tracker: ContractEventTracker,
        _assets: HashMap<Hash, Option<AssetChanges>>,
        _executions: ExecutionsChanges,
        extra_gas_fee: u64,
    ) -> Result<(), ()> {
        // TODO: persist changes in the chain state

        self.add_gas_fee(extra_gas_fee).await
    }

    async fn get_contract_balance_for_gas<'b>(
        &'b mut self,
        contract: &'b Hash,
    ) -> Result<&'b mut (VersionedState, u64), ()> {
        Ok(self.contract_balances
            .entry(contract.clone())
            .or_insert_with(HashMap::new)
            .entry(XELIS_ASSET)
            .or_insert((VersionedState::New, 0)))
    }

    async fn remove_contract_module(&mut self, hash: &'a Hash) -> Result<(), ()> {
        self.contracts.remove(hash);
        Ok(())
    }
}

#[async_trait]
impl<'a> BlockchainApplyState<'a, MockProvider, ()> for MockChainState {
    async fn add_burned_coins(&mut self, asset: &Hash, amount: u64) -> Result<(), ()> {
        *self.burned_coins.entry(asset.clone()).or_insert(0) += amount;
        Ok(())
    }

    async fn add_gas_fee(&mut self, amount: u64) -> Result<(), ()> {
        self.gas_fee += amount;
        Ok(())
    }

    async fn add_burned_fee(&mut self, amount: u64) -> Result<(), ()> {
        self.burned_fee += amount;
        Ok(())
    }

    fn is_mainnet(&self) -> bool {
        self.mainnet
    }
}

impl FeeHelper for AccountStateImpl {
    type Error = ();

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
        self.balances.get(asset).map(|balance| balance.balance).ok_or(())
    }

    fn get_account_ciphertext(&self, asset: &Hash) -> Result<CiphertextCache, Self::Error> {
        self.balances.get(asset).map(|balance| balance.ciphertext.clone()).ok_or(())
    }

    fn get_reference(&self) -> Reference {
        self.reference.clone()
    }

    fn update_account_balance(&mut self, asset: &Hash, balance: u64, ciphertext: Ciphertext) -> Result<(), Self::Error> {
        self.balances.insert(asset.clone(), Balance {
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