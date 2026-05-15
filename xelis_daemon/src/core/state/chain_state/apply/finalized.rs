use std::{
    borrow::Cow,
    collections::{HashMap, hash_map::Entry},
};
use log::{debug, trace, warn};
use indexmap::{IndexSet};
use xelis_common::{
    account::{BalanceType, VersionedBalance, VersionedNonce},
    asset::VersionedAssetData,
    block::{BlockVersion, TopoHeight},
    contract::{
        ContractModule,
        ScheduledExecutionKind,
    },
    crypto::{Hash, PublicKey},
    versioned::{Versioned, VersionedState}
};
use crate::core::{
    state::chain_state::{Account, Echange, ContractManager},
    error::BlockchainError,
    storage::{
        types::TopoHeightMetadata,
        Storage,
        VersionedContractModule,
        VersionedContractBalance,
        VersionedContractData,
        VersionedMultiSig,
        VersionedSupply
    }
};

pub struct FinalizedChainState<'b> {
    // total fees paid in this block
    // this include the gas fee paid by the TXs
    pub total_fees: u64,
    // total fees burned in this block
    pub total_fees_burned: u64,
    pub contract_manager: ContractManager<'b>,
    // current block hash
    pub block_hash: &'b Hash,
    // current block data
    pub is_side_block: bool,
    // Transactions links to store: tx hash -> (blocks linked, executed in, contract)
    pub transactions_links: HashMap<&'b Hash, (IndexSet<&'b Hash>, Option<&'b Hash>, Option<&'b Hash>)>,
    // Balances of the receiver accounts
    pub receiver_balances: HashMap<Cow<'b, PublicKey>, HashMap<Cow<'b, Hash>, VersionedBalance>>,
    // Sender accounts
    // This is used to verify ZK Proofs and store/update nonces
    pub accounts: HashMap<&'b PublicKey, Account<'b>>,
    // Current topoheight of the snapshot
    pub topoheight: TopoHeight,
    // All contracts updated
    pub contracts: HashMap<Cow<'b, Hash>, Option<(VersionedState, Option<Cow<'b, ContractModule>>)>>,
    // Block header version
    pub block_version: BlockVersion,
}

impl<'a> FinalizedChainState<'a> {
    pub async fn apply_changes<S: Storage>(
        mut self,
        storage: &mut S,
        past_emitted_supply: u64,
        block_reward: u64,
    ) -> Result<(), BlockchainError> {
        trace!("apply finalized changes");

        // Set the topoheight for the block
        storage.set_topo_height_for_block(&self.block_hash, self.topoheight).await?;

        // Apply transaction links
        for (tx_hash, (linked_blocks, executed_in, contract)) in self.transactions_links {
            trace!("linking tx {} to blocks", tx_hash);

            let mut blocks = if storage.is_tx_linked_to_blocks(&tx_hash).await? {
                storage.get_blocks_for_tx(&tx_hash).await?
            } else {
                Default::default()
            };

            blocks.extend(linked_blocks.into_iter().cloned());
            storage.set_blocks_for_tx(&tx_hash, &blocks).await?;

            if let Some(executed_in) = executed_in {
                trace!("marking tx {} as executed in block {}", tx_hash, executed_in);
                storage.mark_tx_as_executed_in_block(&tx_hash, &executed_in).await?;
            }

            if let Some(contract) = contract {
                trace!("linking tx {} to contract {}", tx_hash, contract);
                storage.add_tx_for_contract(&contract, &tx_hash).await?;
            }
        }

        // Apply changes for sender accounts
        for (key, account) in &mut self.accounts {
            trace!("Saving nonce {} for {} at topoheight {}", account.nonce, key.as_address(storage.is_mainnet()), self.topoheight);
            storage.set_last_nonce_to(key, self.topoheight, &account.nonce).await?;

            // Save the multisig state if needed
            if let Some((state, multisig)) = account.multisig.as_ref().filter(|(state, _)| state.should_be_stored()) {
                trace!("Saving multisig for {} at topoheight {}", key.as_address(storage.is_mainnet()), self.topoheight);
                let multisig = multisig.as_ref().map(|v| Cow::Borrowed(v));
                let versioned = VersionedMultiSig::new(multisig, state.get_topoheight());
                storage.set_last_multisig_to(key, self.topoheight, versioned).await?;
            }

            let balances = self.receiver_balances.entry(Cow::Borrowed(key)).or_insert_with(HashMap::new);
            // Because account balances are only used to verify the validity of ZK Proofs, we can't store them
            // We have to recompute the final balance for each asset using the existing current balance
            // Otherwise, we could have a front running problem
            // Example: Alice sends 100 to Bob, Bob sends 100 to Charlie
            // But Bob built its ZK Proof with the balance before Alice's transaction
            for (asset, echange) in account.assets.drain() {
                trace!("{} {} updated for {} at topoheight {}", echange.version, asset, key.as_address(storage.is_mainnet()), self.topoheight);
                let Echange { mut version, output_sum, output_balance_used, new_version, .. } = echange;
                trace!("sender output sum: {:?}", output_sum.compress());
                match balances.entry(Cow::Borrowed(asset)) {
                    Entry::Occupied(mut o) => {
                        trace!("{} already has a balance for {} at topoheight {}", key.as_address(storage.is_mainnet()), asset, self.topoheight);
                        // We got incoming funds while spending some
                        // We need to split the version in two
                        // Output balance is the balance after outputs spent without incoming funds
                        // Final balance is the balance after incoming funds + outputs spent
                        // This is a necessary process for the following case:
                        // Alice sends 100 to Bob in block 1000
                        // But Bob build 2 txs before Alice, one to Charlie and one to David
                        // First Tx of Blob is in block 1000, it will be valid
                        // But because of Alice incoming, the second Tx of Bob will be invalid
                        let final_version = o.get_mut();

                        // We got input and output funds, mark it
                        final_version.set_balance_type(BalanceType::Both);

                        // We must build output balance correctly
                        // For that, we use the same balance before any inputs
                        // And deduct outputs
                        // let clean_version = self.storage.get_new_versioned_balance(key, asset, self.topoheight).await?;
                        // let mut output_balance = clean_version.take_balance();
                        // *output_balance.computable()? -= &output_sum;

                        // Determine which balance to use as next output balance
                        // This is used in case TXs that are built at same reference, but
                        // executed in differents topoheights have the output balance reported
                        // to the next topoheight each time to stay valid during ZK Proof verification
                        let output_balance = version.take_balance_with(output_balance_used);

                        // Set to our final version the new output balance
                        final_version.set_output_balance(Some(output_balance));

                        // Build the final balance
                        // All inputs are already added, we just need to substract the outputs
                        let final_balance = final_version.get_mut_balance().computable()?;
                        *final_balance -= output_sum;
                    },
                    Entry::Vacant(e) => {
                        trace!("{} has no balance for {} at topoheight {}", key.as_address(storage.is_mainnet()), asset, self.topoheight);
                        // We have no incoming update for this key
                        // Select the right final version
                        // For that, we must check if we used the output balance and/or if we are not on the last version 
                        let version = if output_balance_used || !new_version {
                            // We must fetch again the version to sum it with the output
                            // This is necessary to build the final balance
                            let (mut new_version, _) = storage.get_new_versioned_balance(key, asset, self.topoheight).await?;
                            // Substract the output sum
                            trace!("{} has no balance for {} at topoheight {}, substract output sum", key.as_address(storage.is_mainnet()), asset, self.topoheight);
                            *new_version.get_mut_balance().computable()? -= output_sum;

                            if self.block_version == BlockVersion::V0 {
                                new_version.set_balance_type(BalanceType::Output);
                            } else {
                                // Report the output balance to the next topoheight
                                // So the edge case where:
                                // Balance at topo 1000 is referenced
                                // Balance updated at topo 1001 as input
                                // TX A is built with reference 1000 but executed at topo 1002
                                // TX B reference 1000 but output balance is at topo 1002 and it include the final balance of (TX A + input at 1001)
                                // So we report the output balance for next TX verification
                                new_version.set_output_balance(Some(version.take_balance_with(output_balance_used)));
                                new_version.set_balance_type(BalanceType::Both);
                            }

                            new_version
                        } else {
                            // Version was based on final balance, all good, nothing to do
                            version.set_balance_type(BalanceType::Output);
                            version
                        };

                        // We have some output, mark it

                        e.insert(version);
                    }
                }
            }
        }

        // Apply the assets
        for (asset, changes) in self.contract_manager.assets {
            if let Some(changes) = changes {
                let (state, data) = changes.data;
                if state.should_be_stored() {
                    trace!("Saving asset {} at topoheight {}", asset, self.topoheight);
                    storage.add_asset(&asset, self.topoheight, VersionedAssetData::new(data, state.get_topoheight())).await?;
                }

                let (state, supply) = changes.circulating_supply;
                if state.should_be_stored() {
                    trace!("Saving supply {} for {} at topoheight {} with prev {:?}", supply, asset, self.topoheight, state.get_topoheight());
                    storage.set_last_circulating_supply_for_asset(&asset, self.topoheight, &VersionedSupply::new(supply, state.get_topoheight())).await?;
                }
            }
        }

        // Start by storing the contracts
        debug!("Storing contracts");
        for (hash, value) in self.contracts {
            if let Some((state, module)) = value {
                if state.should_be_stored() {
                    trace!("Saving contract {} at topoheight {}", hash, self.topoheight);
                    storage.set_last_contract_to(&hash, self.topoheight, &VersionedContractModule::new(module, state.get_topoheight())).await?;
                }
            }
        }

        debug!("Storing contract storage changes");
        // Apply all the contract storage changes
        for (contract, cache) in self.contract_manager.caches {
            // Apply all storage changes
            for (key, value) in cache.storage {
                if let Some((state, value)) = value {
                    if state.should_be_stored() {
                        trace!("Saving contract data {} key {} at topoheight {}", contract, key, self.topoheight);
                        storage.set_last_contract_data_to(&contract, &key, self.topoheight, &VersionedContractData::new(value, state.get_topoheight())).await?;
                    }
                }
            }

            for (asset, data) in cache.balances {
                if let Some((state, balance)) = data {
                    if state.should_be_stored() {
                        trace!("Saving contract balance {} for {} at topoheight {}", balance, asset, self.topoheight);
                        storage.set_last_contract_balance_to(&contract, &asset, self.topoheight, VersionedContractBalance::new(balance, state.get_topoheight())).await?;
                    }
                }
            }
        }

        debug!("applying external transfers");
        // Apply all the transfers to the receiver accounts
        for (key, assets) in self.contract_manager.tracker.aggregated_transfers.iter() {
            for (asset, amount) in assets {
                trace!("Transfering {} {} to {} at topoheight {}", amount, asset, key.as_address(storage.is_mainnet()), self.topoheight);
                let receiver_balance = match self.receiver_balances.entry(Cow::Borrowed(&key)).or_insert_with(HashMap::new).entry(Cow::Borrowed(asset)) {
                    Entry::Occupied(o) => o.into_mut(),
                    Entry::Vacant(e) => {
                        let (version, _) = storage.get_new_versioned_balance(&key, &asset, self.topoheight).await?;
                        e.insert(version)
                    }
                }.get_mut_balance().computable()?;

                *receiver_balance += *amount;
            }
        }

        // Apply all the contract outputs
        debug!("storing contract outputs");
        for (key, logs) in self.contract_manager.logs {
            storage.set_contract_logs_for_caller(&key, &logs).await?;
        }

        // Apply all scheduled executions at their topoheight
        debug!("applying scheduled executions at topoheights");
        for hash in self.contract_manager.executions.at_topoheight {
            let execution = self.contract_manager.executions.executions.get(&hash)
                .ok_or(BlockchainError::ScheduledExecutionNotFound)?;

            if let ScheduledExecutionKind::TopoHeight(execution_topoheight) = execution.kind {
                trace!("storing scheduled execution of contract {} with caller {} at topoheight {}", execution.contract, execution.hash, self.topoheight);
                storage.set_contract_scheduled_execution_at_topoheight(&execution.contract, self.topoheight, &execution, execution_topoheight).await?;
            } else {
                warn!("scheduled execution {} kind mismatch, expected TopoHeight", execution.hash);
            }
        }

        // Apply all event callback registrations
        debug!("storing event callbacks registrations");
        for ((contract, event_id), listeners) in self.contract_manager.events_listeners {
            // Remove all previously processed for this event
            // So in case it was registered, consumed, and re registered in the same block, we only keep the last one
            let mut processed_listeners = self.contract_manager.events_processed.get_mut(&(contract.clone(), event_id));

            for (listener_contract, callback) in listeners {
                trace!("storing event callback registration for event {} of contract {} to listener {} at topoheight {}", event_id, contract, listener_contract, self.topoheight);
                // If this listener was consumed (triggered) earlier in the same block and is now
                // re-registering, remove it from the tombstone set so it won't be written as None.
                if processed_listeners.as_mut().map_or(false, |v| v.remove(&listener_contract)) {
                    trace!("listener {} re-registered after being consumed for event {} of contract {}, keeping new registration", listener_contract, event_id, contract);
                }

                let prev_topo = storage.get_event_callback_for_contract_at_maximum_topoheight(
                    &contract,
                    event_id,
                    &listener_contract,
                    self.topoheight,
                ).await?
                .map(|(topo, _)| topo);

                storage.set_last_contract_event_callback(
                    &contract,
                    event_id,
                    &listener_contract,
                    Versioned::new(Some(callback), prev_topo),
                    self.topoheight
                ).await?;
            }
        }

        for ((contract, event_id), listeners) in self.contract_manager.events_processed {
            for listener_contract in listeners {
                trace!("removing event callback registration for event {} of contract {} to listener {} at topoheight {}", event_id, contract, listener_contract, self.topoheight);
                let prev_topo = storage.get_event_callback_for_contract_at_maximum_topoheight(
                    &contract,
                    event_id,
                    &listener_contract,
                    self.topoheight,
                ).await?
                .map(|(topo, _)| topo);

                storage.set_last_contract_event_callback(
                    &contract,
                    event_id,
                    &listener_contract,
                    Versioned::new(None, prev_topo),
                    self.topoheight
                ).await?;
            }
        }

        // Apply all balances changes at topoheight
        // We injected the sender balances in the receiver balances previously
        debug!("applying balances");
        for (account, balances) in self.receiver_balances {
            // If the account has no nonce set, set it to 0
            if !self.accounts.contains_key(account.as_ref()) && !storage.has_nonce(&account).await? {
                debug!("{} has now a balance but without any nonce registered, set default (0) nonce", account.as_address(storage.is_mainnet()));
                storage.set_last_nonce_to(&account, self.topoheight, &VersionedNonce::new(0, None)).await?;
            }

            // Mark it as registered at this topoheight
            if !storage.is_account_registered_for_topoheight(&account, self.topoheight).await? {
                storage.set_account_registration_topoheight(&account, self.topoheight).await?;
            }

            for (asset, version) in balances {
                trace!("Saving versioned balance {} for {} at topoheight {}", version, account.as_address(storage.is_mainnet()), self.topoheight);
                storage.set_last_balance_to(&account, &asset, self.topoheight, &version).await?;
            }
        }

        // Finally, update the topoheight metadata
        debug!("updating topoheight metadata to {}", self.topoheight);
        let emitted_supply = past_emitted_supply + block_reward;
        let metadata = TopoHeightMetadata {
            block_reward,
            emitted_supply,
            total_fees: self.total_fees,
            total_fees_burned: self.total_fees_burned,
            is_side_block: self.is_side_block,
        };

        storage.set_metadata_at_topoheight(self.topoheight, metadata).await?;

        Ok(())
    }
}
