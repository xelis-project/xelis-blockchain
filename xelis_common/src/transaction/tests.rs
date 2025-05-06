use std::{borrow::Cow, collections::HashMap};
use async_trait::async_trait;
use curve25519_dalek::Scalar;
use indexmap::IndexSet;
use xelis_vm::{Chunk, Environment, Module};
use crate::{
    account::{CiphertextCache, Nonce},
    api::{DataElement, DataValue},
    block::BlockVersion,
    config::{BURN_PER_CONTRACT, COIN_VALUE, XELIS_ASSET},
    crypto::{
        elgamal::{Ciphertext, PedersenOpening},
        proofs::PC_GENS,
        Address,
        Hash,
        Hashable,
        KeyPair,
        PublicKey
    },
    serializer::Serializer,
    transaction::{
        builder::{ContractDepositBuilder, DeployContractBuilder, InvokeContractBuilder},
        MultiSigPayload,
        TransactionType,
        TxVersion,
        MAX_TRANSFER_COUNT
    }
};
use super::{
    extra_data::{
        derive_shared_key_from_opening,
        PlaintextData
    },
    builder::{
        AccountState,
        FeeBuilder,
        FeeHelper,
        TransactionBuilder,
        TransactionTypeBuilder,
        TransferBuilder,
        MultiSigBuilder
    },
    verify::BlockchainVerificationState,
    BurnPayload,
    Reference,
    Role,
    Transaction
};

struct AccountChainState {
    balances: HashMap<Hash, Ciphertext>,
    nonce: Nonce,
}

struct ChainState {
    accounts: HashMap<PublicKey, AccountChainState>,
    multisig: HashMap<PublicKey, MultiSigPayload>,
    contracts: HashMap<Hash, Module>,
    env: Environment,
}

impl ChainState {
    fn new() -> Self {
        Self {
            accounts: HashMap::new(),
            multisig: HashMap::new(),
            contracts: HashMap::new(),
            env: Environment::new(),
        }
    }
}

#[derive(Clone)]
struct Balance {
    ciphertext: CiphertextCache,
    balance: u64,
}

#[derive(Clone)]
struct Account {
    balances: HashMap<Hash, Balance>,
    keypair: KeyPair,
    nonce: Nonce,
}

impl Account {
    fn new() -> Self {
        Self {
            balances: HashMap::new(),
            keypair: KeyPair::new(),
            nonce: 0,
        }
    }

    fn set_balance(&mut self, asset: Hash, balance: u64) {
        let ciphertext = self.keypair.get_public_key().encrypt(balance);
        self.balances.insert(asset, Balance {
            balance,
            ciphertext: CiphertextCache::Decompressed(ciphertext),
        });
    }

    fn address(&self) -> Address {
        self.keypair.get_public_key().to_address(false)
    }
}

struct AccountStateImpl {
    balances: HashMap<Hash, Balance>,
    reference: Reference,
    nonce: Nonce,
}

fn create_tx_for(account: Account, destination: Address, amount: u64, extra_data: Option<DataElement>) -> Transaction {
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


    let builder = TransactionBuilder::new(TxVersion::V1, account.keypair.get_public_key().compress(), None, data, FeeBuilder::default());
    let estimated_size = builder.estimate_size();
    let tx = builder.build(&mut state, &account.keypair).unwrap();
    assert!(estimated_size == tx.size(), "expected {} bytes got {} bytes", tx.size(), estimated_size);
    assert!(tx.to_bytes().len() == estimated_size);

    tx
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
        ciphertext: CiphertextCache::Decompressed(alice.keypair.get_public_key().encrypt(100 * COIN_VALUE)),
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

    let mut state = ChainState::new();

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
    tx.verify(&hash, &mut state).await.unwrap();

    // Check Bob balance
    let balance = bob.keypair.decrypt_to_point(&state.accounts[&bob.keypair.get_public_key().compress()].balances[&XELIS_ASSET]);    
    assert_eq!(balance, Scalar::from(50u64) * PC_GENS.B);

    // Check Alice balance
    let balance = alice.keypair.decrypt_to_point(&state.accounts[&alice.keypair.get_public_key().compress()].balances[&XELIS_ASSET]);
    assert_eq!(balance, Scalar::from((100u64 * COIN_VALUE) - (50 + tx.fee)) * PC_GENS.B);
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

        tx
    };

    let mut state = ChainState::new();

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
    tx.verify(&hash, &mut state).await.unwrap();

    // Check Alice balance
    let balance = alice.keypair.decrypt_to_point(&state.accounts[&alice.keypair.get_public_key().compress()].balances[&XELIS_ASSET]);
    assert_eq!(balance, Scalar::from((100u64 * COIN_VALUE) - (50 * COIN_VALUE + tx.fee)) * PC_GENS.B);
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
            chunk_id: 0,
            max_gas: 1000,
            parameters: Vec::new(),
            deposits: [
                (XELIS_ASSET, ContractDepositBuilder {
                    amount: 50 * COIN_VALUE,
                    private: false
                })
            ].into_iter().collect()
        });
        let builder = TransactionBuilder::new(TxVersion::V2, alice.keypair.get_public_key().compress(), None, data, FeeBuilder::default());
        let estimated_size = builder.estimate_size();
        let tx = builder.build(&mut state, &alice.keypair).unwrap();
        assert!(estimated_size == tx.size());
        assert!(tx.to_bytes().len() == estimated_size);

        tx
    };

    let mut state = ChainState::new();
    let mut module = Module::new();
    module.add_entry_chunk(Chunk::new());
    state.contracts.insert(Hash::zero(), module);

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
    tx.verify(&hash, &mut state).await.unwrap();

    // Check Alice balance
    let balance = alice.keypair.decrypt_to_point(&state.accounts[&alice.keypair.get_public_key().compress()].balances[&XELIS_ASSET]);
    // 50 coins deposit + tx fee + 1000 gas fee
    let total_spend = (50 * COIN_VALUE) + tx.fee + 1000;

    assert_eq!(balance, Scalar::from((100 * COIN_VALUE) - total_spend) * PC_GENS.B);
}


#[tokio::test]
async fn test_tx_deploy_contract() {
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

        let mut module = Module::new();
        module.add_chunk(Chunk::new());
        let data = TransactionTypeBuilder::DeployContract(DeployContractBuilder {
            module: module.to_hex(),
            invoke: None
        });
        let builder = TransactionBuilder::new(TxVersion::V2, alice.keypair.get_public_key().compress(), None, data, FeeBuilder::default());
        let estimated_size = builder.estimate_size();
        let tx = builder.build(&mut state, &alice.keypair).unwrap();
        assert!(estimated_size == tx.size(), "expected {} bytes got {} bytes", tx.size(), estimated_size);
        assert!(tx.to_bytes().len() == estimated_size);

        tx
    };

    let mut state = ChainState::new();

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
    tx.verify(&hash, &mut state).await.unwrap();

    // Check Alice balance
    let balance = alice.keypair.decrypt_to_point(&state.accounts[&alice.keypair.get_public_key().compress()].balances[&XELIS_ASSET]);
    // 1 XEL for contract deploy, tx fee
    let total_spend = BURN_PER_CONTRACT + tx.fee;

    assert_eq!(balance, Scalar::from((100 * COIN_VALUE) - total_spend) * PC_GENS.B);
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

        tx
    };

    // Create the chain state
    let mut state = ChainState::new();

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
    tx.verify(&hash, &mut state).await.unwrap();
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

        tx
    };

    let mut state = ChainState::new();

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
    tx.verify(&hash, &mut state).await.unwrap();

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

        tx.finalize(&alice.keypair)
    };

    // Create the chain state
    let mut state = ChainState::new();

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
    tx.verify(&hash, &mut state).await.unwrap();
}

#[async_trait]
impl<'a> BlockchainVerificationState<'a, ()> for ChainState {

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

    async fn get_environment(&mut self) -> Result<&Environment, ()> {
        Ok(&self.env)
    }

    async fn set_contract_module(
        &mut self,
        hash: &'a Hash,
        module: &'a Module
    ) -> Result<(), ()> {
        self.contracts.insert(hash.clone(), module.clone());
        Ok(())
    }

    async fn load_contract_module(
        &mut self,
        hash: &'a Hash
    ) -> Result<bool, ()> {
        Ok(self.contracts.contains_key(hash))
    }

    async fn get_contract_module_with_environment(
        &self,
        contract: &'a Hash
    ) -> Result<(&Module, &Environment), ()> {
        let module = self.contracts.get(contract).ok_or(())?;
        Ok((module, &self.env))
    }
}

impl FeeHelper for AccountStateImpl {
    type Error = ();

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
            ciphertext: CiphertextCache::Decompressed(ciphertext),
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