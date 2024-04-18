use std::collections::HashMap;
use async_trait::async_trait;
use crate::{
    account::CiphertextCache,
    api::{DataElement, DataValue},
    config::{COIN_VALUE, XELIS_ASSET},
    crypto::{
        elgamal::{Ciphertext, PedersenOpening},
        Address,
        Hash,
        KeyPair,
        PublicKey
    },
    serializer::Serializer,
    transaction::{TransactionType, MAX_TRANSFER_COUNT}
};
use super::{
    aead::{
        derive_aead_key_from_ct,
        derive_aead_key_from_opening,
        PlaintextData
    },
    builder::{
        AccountState,
        FeeBuilder,
        FeeHelper,
        TransactionBuilder,
        TransactionTypeBuilder,
        TransferBuilder
    },
    verify::BlockchainVerificationState,
    BurnPayload,
    Reference,
    Role,
    Transaction
};

struct AccountChainState {
    balances: HashMap<Hash, Ciphertext>,
    nonce: u64,
}

struct ChainState {
    accounts: HashMap<PublicKey, AccountChainState>,
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
    nonce: u64,
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
    nonce: u64,
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
    }]);


    let builder = TransactionBuilder::new(0, account.keypair.get_public_key().compress(), data, FeeBuilder::Multiplier(1f64));
    let tx = builder.build(&mut state, &account.keypair).unwrap();

    tx
}

#[test]
fn test_encrypt_decrypt() {
    let r = PedersenOpening::generate_new();
    let key = derive_aead_key_from_opening(&r);
    let message = "Hello, World!".as_bytes().to_vec();

    let plaintext = PlaintextData(message.clone());
    let cipher = plaintext.encrypt_in_place(&key);
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
    let cipher = transfer.extra_data.clone().unwrap();
    // Verify the extra data from alice (sender)
    {
        let alice_ct = transfer.get_ciphertext(Role::Sender).decompress().unwrap();
        let key = derive_aead_key_from_ct(&alice.keypair.get_private_key(), &alice_ct);
        let decrypted = cipher.clone().decrypt_in_place(&key).unwrap();
        assert_eq!(decrypted.0, payload.to_bytes());
    }

    // Verify the extra data from bob (receiver)
    {
        let bob_ct = transfer.get_ciphertext(Role::Receiver).decompress().unwrap();
        let key = derive_aead_key_from_ct(&bob.keypair.get_private_key(), &bob_ct);
        let decrypted = cipher.clone().decrypt_in_place(&key).unwrap();
        assert_eq!(decrypted.0, payload.to_bytes());
    }

    // Verify the extra data from alice (sender) with the wrong key
    {
        let alice_ct = transfer.get_ciphertext(Role::Sender).decompress().unwrap();
        let key = derive_aead_key_from_ct(&bob.keypair.get_private_key(), &alice_ct);
        let decrypted = cipher.decrypt_in_place(&key);
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

    let mut state = ChainState {
        accounts: HashMap::new(),
    };

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

    tx.verify(&mut state).await.unwrap();
}

#[tokio::test]
async fn test_burn_tx_verify() {
    let mut alice = Account::new();
    let mut bob = Account::new();

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
    
        let data = TransactionTypeBuilder::Burn(BurnPayload {
            amount: 50 * COIN_VALUE,
            asset: XELIS_ASSET,
        });
        let builder = TransactionBuilder::new(0, alice.keypair.get_public_key().compress(), data, FeeBuilder::Multiplier(1f64));
        builder.build(&mut state, &alice.keypair).unwrap()
    };

    let mut state = ChainState {
        accounts: HashMap::new(),
    };

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

    tx.verify(&mut state).await.unwrap();
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
        let builder = TransactionBuilder::new(0, alice.keypair.get_public_key().compress(), data, FeeBuilder::Multiplier(1f64));
        builder.build(&mut state, &alice.keypair).unwrap()
    };

    // Create the chain state
    let mut state = ChainState {
        accounts: HashMap::new(),
    };

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

    assert!(tx.verify(&mut state).await.is_ok());
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
        account: &'a PublicKey,
        asset: &'a Hash,
    ) -> Result<&'b mut Ciphertext, ()> {
        self.accounts.get_mut(account).and_then(|account| account.balances.get_mut(asset)).ok_or(())
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
    ) -> Result<u64, ()> {
        self.accounts.get(account).map(|account| account.nonce).ok_or(())
    }

    /// Apply a new nonce to an account
    async fn update_account_nonce(
        &mut self,
        account: &'a PublicKey,
        new_nonce: u64
    ) -> Result<(), ()> {
        self.accounts.get_mut(account).map(|account| account.nonce = new_nonce).ok_or(())
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

    fn get_nonce(&self) -> Result<u64, Self::Error> {
        Ok(self.nonce)
    }

    fn update_nonce(&mut self, new_nonce: u64) -> Result<(), Self::Error> {
        self.nonce = new_nonce;
        Ok(())
    }
}