use xelis_common::contract::ContractProvider;

use crate::core::state::chain_state::ChainStateProvider;

pub trait ApplicableChainStateProvider: ChainStateProvider + ContractProvider {}

impl<T: ChainStateProvider + ContractProvider> ApplicableChainStateProvider for T {}