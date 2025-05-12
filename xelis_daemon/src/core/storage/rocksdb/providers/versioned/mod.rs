use crate::core::storage::{RocksStorage, VersionedProvider};

mod balance;
mod contract;
mod multisig;
mod nonce;
mod registrations;
mod asset;
mod cache;
mod dag_order;

impl VersionedProvider for RocksStorage {}