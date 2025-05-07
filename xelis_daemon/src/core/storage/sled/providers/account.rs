use async_trait::async_trait;
use log::{trace, debug, error};
use xelis_common::{
    crypto::PublicKey,
    serializer::Serializer,
    block::TopoHeight,
};
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::{
        AccountProvider,
        AssetProvider,
        BalanceProvider,
        NetworkProvider,
        NonceProvider,
        SledStorage
    }
};

fn prefixed_db_key(topoheight: TopoHeight, key: &PublicKey) -> [u8; 40] {
    prefixed_db_key_no_u64(&topoheight.to_bytes(), key)
}

fn prefixed_db_key_no_u64(topoheight: &[u8], key: &PublicKey) -> [u8; 40] {
    let mut buf = [0u8; 40];
    buf[0..8].copy_from_slice(&topoheight);
    buf[8..40].copy_from_slice(key.as_bytes());
    buf
}

#[async_trait]
impl AccountProvider for SledStorage {
    async fn get_account_registration_topoheight(&self, key: &PublicKey) -> Result<TopoHeight, BlockchainError> {
        trace!("get account registration topoheight: {}", key.as_address(self.network.is_mainnet()));
        self.load_from_disk(&self.registrations, key.as_bytes(), DiskContext::AccountRegistrationTopoHeight)
    }

    async fn set_account_registration_topoheight(&mut self, key: &PublicKey, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("set account registration topoheight: {} {}", key.as_address(self.network.is_mainnet()), topoheight);
        if let Some(old) = Self::insert_into_disk(self.snapshot.as_mut(), &self.registrations, key.as_bytes(), &topoheight.to_be_bytes())? {
            Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.registrations_prefixed, &prefixed_db_key_no_u64(&old, key))?;
        }

        Self::insert_into_disk(self.snapshot.as_mut(), &self.registrations_prefixed, &prefixed_db_key(topoheight, key), &[])?;

        Ok(())
    }

    async fn delete_account_registration(&mut self, key: &PublicKey) -> Result<(), BlockchainError> {
        trace!("delete account registration topoheight: {}", key.as_address(self.network.is_mainnet()));

        let value = self.load_optional_from_disk::<TopoHeight>(&self.registrations, key.as_bytes())?;
        if let Some(topo) = value {
            let k = prefixed_db_key(topo, key);
            Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.registrations_prefixed, &k)?;
            Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.registrations, key.as_bytes())?;
        }

        Ok(())
    }

    async fn is_account_registered(&self, key: &PublicKey) -> Result<bool, BlockchainError> {
        trace!("is account registered: {}", key.as_address(self.network.is_mainnet()));
        let value = self.load_optional_from_disk::<TopoHeight>(&self.registrations, key.as_bytes())?;
        if let Some(topo) = value {
            let k = prefixed_db_key(topo, key);
            return self.contains_data(&self.registrations_prefixed, &k)
        }

        Ok(false)
    }

    async fn is_account_registered_for_topoheight(&self, key: &PublicKey, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("is account registered for topoheight: {} {}", key.as_address(self.network.is_mainnet()), topoheight);
        if !self.is_account_registered(key).await? {
            debug!("account {} is not registered", key.as_address(self.network.is_mainnet()));
            return Ok(false);
        }

        let registration_topoheight = self.get_account_registration_topoheight(key).await?;
        Ok(registration_topoheight <= topoheight)
    }

    async fn delete_registrations_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete registrations at topoheight: {}", topoheight);
        for el in Self::scan_prefix(self.snapshot.as_ref(), &self.registrations_prefixed, &topoheight.to_bytes()) {
            let k = el?;
            Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.registrations_prefixed, &k)?;

            let key = &k[8..40];
            Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.registrations, key)?;
        }

        Ok(())
    }

    // Get all keys that got registered in the range given
    async fn get_registered_keys<'a>(&'a self, minimum_topoheight: Option<TopoHeight>, maximum_topoheight: Option<TopoHeight>) -> Result<impl Iterator<Item = Result<PublicKey, BlockchainError>> + 'a, BlockchainError> {
        trace!("get partial keys  minimum_topoheight: {:?}, maximum_topoheight: {:?}", minimum_topoheight, maximum_topoheight);

        Ok(
            Self::iter_keys(self.snapshot.as_ref(), &self.registrations_prefixed)
                .map(move |el| {
                    let key = el?;

                    if minimum_topoheight.is_some() || maximum_topoheight.is_some() {
                        let topo = TopoHeight::from_bytes(&key[0..8])?;

                        // Skip if not in range
                        if minimum_topoheight.is_some_and(|v| topo < v) || maximum_topoheight.is_some_and(|v| topo > v) {
                            trace!("skipping {} at {}: {:?} {:?}", PublicKey::from_bytes(&key[8..40])?.as_address(self.is_mainnet()), topo, minimum_topoheight, maximum_topoheight);
                            return Ok(None);
                        }
                    }

                    let key = PublicKey::from_bytes(&key[8..40])?;
                    Ok(Some(key))
                })
                .filter_map(Result::transpose)
        )
    }

    async fn has_key_updated_in_range(&self, key: &PublicKey, minimum_topoheight: TopoHeight, maximum_topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("has key {} updated in range min topoheight {} and max topoheight {}", key.as_address(self.is_mainnet()), minimum_topoheight, maximum_topoheight);
        // check first that this address has nonce, if no returns None
        if !self.has_nonce(key).await? {
            return Ok(false)
        }

        // fast path check the latest nonce
        let (topo, mut version) = self.get_last_nonce(key).await?;
        trace!("Last version of nonce for {} is at topoheight {}", key.as_address(self.is_mainnet()), topo);

        // if it's the latest and its under the maximum topoheight and above minimum topoheight
        if topo >= minimum_topoheight && topo <= maximum_topoheight {
            trace!("Last version nonce (valid) found at {} (maximum topoheight = {})", topo, maximum_topoheight);
            return Ok(true)
        }

        // otherwise, we have to go through the whole chain
        while let Some(previous) = version.get_previous_topoheight() {
            // we are under the minimum topoheight, we can stop
            if previous < minimum_topoheight {
                break;
            }

            let previous_version = self.get_nonce_at_exact_topoheight(key, previous).await?;
            trace!("previous nonce version is at {}", previous);
            if previous <= maximum_topoheight {
                trace!("Highest version nonce found at {} (maximum topoheight = {})", previous, maximum_topoheight);
                return Ok(true)
            }

            // security in case of DB corruption
            if let Some(value) = previous_version.get_previous_topoheight() {
                if value > previous {
                    error!("FATAL ERROR: Previous topoheight ({}) should not be higher than current version ({})!", value, previous);
                    return Err(BlockchainError::Unknown)
                }
            }
            version = previous_version;
        }

        // if we are here, we didn't find any nonce in the range
        // it start to be more and more heavy...
        // lets check on balances now...

        // check that we have a VersionedBalance between range given
        for res in self.get_assets_for(key).await? {
            let asset = res?;
            let (topo, mut version) = self.get_last_balance(key, &asset).await?;
            if topo >= minimum_topoheight && topo <= maximum_topoheight {
                return Ok(true)
            }

            while let Some(previous) = version.get_previous_topoheight() {
                // we are under the minimum topoheight, we can stop
                if previous < minimum_topoheight {
                    break;
                }

                let previous_version = self.get_balance_at_exact_topoheight(key, &asset, previous).await?;
                if previous <= maximum_topoheight {
                    return Ok(true)
                }

                // security in case of DB corruption
                if let Some(value) = previous_version.get_previous_topoheight() {
                    if value > previous {
                        error!("FATAL ERROR: Previous topoheight for balance ({}) should not be higher than current version of balance ({})!", value, previous);
                        return Err(BlockchainError::Unknown)
                    }
                }
                version = previous_version;
            }
        }

        Ok(false)
    }
}