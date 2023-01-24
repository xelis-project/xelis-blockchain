use anyhow::Result;
use xelis_common::{json_rpc::JsonRPCClient, crypto::{key::KeyPair, address::Address, hash::Hash}, api::daemon::GetBalanceParams};

pub struct Account {
    client: JsonRPCClient,
    keypair: KeyPair   
}

impl Account {
    pub fn new(daemon_address: String, keypair: KeyPair) -> Self {
        let client = JsonRPCClient::new(daemon_address);

        Self {
            keypair,
            client
        }
    }

    pub fn get_address(&self) -> Address<'_> {
        self.keypair.get_public_key().to_address()
    }

    pub fn load_balance(&self, asset: Hash) -> Result<u64> {
        let balance = self.client.call_with::<GetBalanceParams, u64>("get_balance", &GetBalanceParams { address: self.get_address(), asset })?;
        Ok(balance)
    }
}