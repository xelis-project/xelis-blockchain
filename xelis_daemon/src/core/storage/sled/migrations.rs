use log::{debug, warn};
use xelis_common::{
    asset::AssetData,
    config::{COIN_DECIMALS, MAXIMUM_SUPPLY, VERSION, XELIS_ASSET},
    network::Network,
    serializer::Serializer
};
use crate::core::{error::BlockchainError, hard_fork};
use super::{SledStorage, DB_VERSION};

impl SledStorage {
    pub(super) fn handle_migrations(&mut self) -> Result<(), BlockchainError> {
        let migrate = match self.extra.get(DB_VERSION)? {
            Some(version) => !hard_fork::is_version_matching_requirement(&String::from_utf8_lossy(&version), "1.17")?,
            None => true
        };

        if migrate {
            warn!("Migrating data");
            let ticker = match self.network {
                Network::Mainnet => "XEL".to_owned(),
                _ => "XET".to_owned(),
            };

            // We need to patch the ticker for XELIS asset
            let data = AssetData::new(COIN_DECIMALS, "XELIS".to_owned(), ticker, Some(MAXIMUM_SUPPLY), None);
            let key = Self::get_asset_key(&XELIS_ASSET, 0);

            self.assets_prefixed.insert(&key, data.to_bytes())?;
        }

        debug!("set DB version to {}", VERSION);
        self.extra.insert(DB_VERSION, VERSION)?;

        Ok(())
    }
}