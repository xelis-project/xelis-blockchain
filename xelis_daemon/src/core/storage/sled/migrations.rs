use log::debug;
use xelis_common::config::VERSION;
use crate::core::error::BlockchainError;
use super::{SledStorage, DB_VERSION};

impl SledStorage {
    pub(super) fn handle_migrations(&mut self) -> Result<(), BlockchainError> {
        debug!("set DB version to {}", VERSION);
        self.extra.insert(DB_VERSION, VERSION)?;

        Ok(())
    }
}