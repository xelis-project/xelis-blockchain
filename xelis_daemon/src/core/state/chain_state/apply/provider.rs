use xelis_common::contract::ContractProvider;

use crate::core::state::chain_state::ChainStateProvider;

pub trait ApplicableChainStateProvider: ChainStateProvider + for<'ty> ContractProvider<'ty> {}

impl<T: ChainStateProvider + for<'ty> ContractProvider<'ty>> ApplicableChainStateProvider for T {}