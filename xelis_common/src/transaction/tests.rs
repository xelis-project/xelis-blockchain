use std::collections::HashMap;
use async_trait::async_trait;
use crate::{account::CiphertextCache, config::{COIN_VALUE, XELIS_ASSET}, crypto::{elgamal::Ciphertext, Address, Hash, KeyPair, PublicKey}};
use super::{builder::{AccountState, FeeBuilder, TransactionBuilder, TransactionTypeBuilder, TransferBuilder}, verify::BlockchainVerificationState, Reference, Transaction};

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

struct AccountStateImpl<'a> {
    balances: &'a mut HashMap<Hash, Balance>,
    reference: Reference,
}

fn create_tx_for(account: &mut Account, destination: Address, amount: u64) -> Transaction {
    let mut state = AccountStateImpl {
        balances: &mut account.balances,
        reference: Reference {
            topoheight: 0,
            hash: Hash::zero(),
        },
    };

    let data = TransactionTypeBuilder::Transfers(vec![TransferBuilder {
        amount,
        destination,
        asset: XELIS_ASSET,
        extra_data: None,
    }]);


    let builder = TransactionBuilder::new(0, account.keypair.get_public_key().compress(), data, FeeBuilder::Multiplier(1f64), 0);
    let tx = builder.build(&mut state, &account.keypair).unwrap();

    tx
}

#[tokio::test]
async fn test_tx_verify() {
    let mut alice = Account::new();
    let mut bob = Account::new();

    alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
    bob.set_balance(XELIS_ASSET, 0);

    // Alice account is cloned to not be updated as it is used for verification and need current state
    let tx = create_tx_for(&mut alice.clone(), bob.address(), 50);

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

#[async_trait]
impl<'a> BlockchainVerificationState<'a, ()> for ChainState {
    /// Get the balance ciphertext for a receiver account
    async fn get_receiver_balance<'b>(
        &'b mut self,
        account: &'a PublicKey,
        asset: &'a Hash,
    ) -> Result<&'b mut Ciphertext, ()> {
        self.accounts.get_mut(account).and_then(|account| account.balances.get_mut(asset)).ok_or(())
    }

    /// Get the balance ciphertext used for verification of funds for the sender account
    async fn get_sender_verification_balance<'b>(
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

impl<'a> AccountState for AccountStateImpl<'a> {
    type Error = ();

    fn is_mainnet(&self) -> bool {
        false
    }

    fn account_exists(&self, _: &PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
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
}