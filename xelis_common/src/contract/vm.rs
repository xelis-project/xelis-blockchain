use std::{
    borrow::Cow,
    collections::HashMap,
    sync::Arc
};

use thiserror::Error;
use curve25519_dalek::Scalar;
use log::{debug, log, trace, warn, Level};
use indexmap::IndexMap;
use xelis_vm::{ModuleMetadata, Reference, VM, VMError, ValueCell};

use crate::{
    config::{TX_GAS_BURN_PERCENT, XELIS_ASSET},
    contract::{
        Source,
        ChainState,
        ContractLog,
        ContractProvider,
        ContractProviderWrapper,
        InterContractPermission,
        ContractMetadata,
        ContractCache
    },
    crypto::{
        elgamal::{Ciphertext, CompressedPublicKey},
        Hash
    },
    transaction::{
        verify::{BlockchainApplyState, ContractEnvironment, DecompressedDepositCt},
        ContractDeposit,
        Transaction
    }
};

// Actual constructor hook id
pub const HOOK_CONSTRUCTOR_ID: u8 = 0;

#[derive(Debug)]
pub enum InvokeContract {
    Entry(u16),
    Hook(u8),
    // chunk id, allow registering executions for block end
    Chunk(u16, bool),
}

#[derive(Debug, Clone)]
pub enum ContractCaller<'a> {
    Transaction(&'a Hash, &'a Arc<Transaction>),
    // Scheduled is formed from hash(contract, topoheight)
    // to simulate a TX hash for logs and tracking
    // Second hash is the contract hash
    Scheduled(Cow<'a, Hash>, Cow<'a, Hash>)
}

impl<'a> ContractCaller<'a> {
    pub fn get_hash(&self) -> Cow<'a, Hash> {
        match self {
            Self::Transaction(hash, _) => Cow::Borrowed(hash),
            Self::Scheduled(hash, _) => hash.clone(),
        }
    }
}

#[derive(Error, Debug)]
pub enum ContractError<E> {
    #[error(transparent)]
    State(E),
    #[error(transparent)]
    VM(#[from] VMError),
    #[error("overflow during gas calculation")]
    GasOverflow,
    #[error("contract cache not found")]
    ContractCache,
    #[error("gas balance not found for contract")]
    GasBalance,
    #[error("Deposit decompressed not found")]
    DepositNotFound,
}

// Create the VM and run the required contrac twith all needed functions
pub(crate) async fn run_virtual_machine<'a, P: ContractProvider>(
    contract_environment: ContractEnvironment<'a, P>,
    chain_state: &mut ChainState<'a>,
    invoke: InvokeContract,
    contract: Cow<'a, Hash>,
    deposits: IndexMap<Hash, ContractDeposit>,
    parameters: impl DoubleEndedIterator<Item = ValueCell>,
    max_gas: u64,
) -> Result<(u64, u64, Option<u64>), VMError> {
    debug!("run virtual machine with max gas {}", max_gas);
    let mut vm = VM::default();

    // Insert the module to load
    let metadata = ContractMetadata {
        contract_executor: contract.as_ref().clone(),
        contract_caller: None,
        deposits,
    };
    vm.append_module(ModuleMetadata {
        module: Reference::Borrowed(contract_environment.module),
        metadata: Reference::Shared(Arc::new(metadata)),
        environment: Reference::Borrowed(contract_environment.environment),
    })?;

    // Invoke the needed chunk
    // This is the first chunk to be called
    match invoke {
        InvokeContract::Entry(entry) => {
            vm.invoke_entry_chunk(entry)?;
        },
        InvokeContract::Hook(hook) => {
            if !vm.invoke_hook_id(hook)? {
                warn!("Invoke contract {} hook {} not found", contract, hook);
                return Ok((0, max_gas, None))
            }
        },
        InvokeContract::Chunk(chunk, allow_executions) => {
            if !contract_environment.module.is_callable_chunk(chunk as usize) {
                warn!("Invoke contract {} chunk {} not found", contract, chunk);
                return Ok((0, max_gas, None))
            }

            vm.invoke_chunk_id(chunk as usize)?;
            chain_state.allow_executions = allow_executions;
        }
    }

    // We need to push it in reverse order because the VM will pop them in reverse order
    for constant in parameters.rev() {
        trace!("Pushing constant: {}", constant);
        vm.push_stack(constant)?;
    }

    let debug_mode = chain_state.debug_mode;
    let context = vm.context_mut();

    // Set the gas limit for the VM
    context.set_gas_limit(max_gas);

    // insert the chain state separetly to avoid to give the S type
    context.insert_mut(chain_state);
    // insert the storage through our wrapper
    // so it can be easily mocked
    context.insert(ContractProviderWrapper(contract_environment.provider));

    // We need to handle the result of the VM
    let res = vm.run().await;

    // To be sure that we don't have any overflow
    // We take the minimum between the gas used and the max gas
    let context = vm.context();
    let gas_usage = context
        .current_gas_usage()
        .min(max_gas);
    let vm_max_gas = context.get_gas_limit();

    let exit_code = match res {
        Ok(res) => {
            let level = if debug_mode {
                Level::Info
            } else {
                Level::Debug
            };
            log!(level, "Invoke contract {} result: {:#}", contract, res);
            // If the result return 0 as exit code, it means that everything went well
            let exit_code = res.as_u64().ok();
            exit_code
        },
        Err(err) => {
            let level = if debug_mode {
                Level::Error
            } else {
                Level::Debug
            };
            log!(level, "Invoke contract {} error: {:#}", contract, err);
            None
        }
    };

    Ok((gas_usage, vm_max_gas, exit_code))
}

// Invoke a contract from a transaction
// Note that the contract must be already loaded by calling
// `is_contract_available`
pub async fn invoke_contract<'a, P: ContractProvider, E, B: BlockchainApplyState<'a, P, E>>(
    caller: ContractCaller<'a>,
    state: &mut B,
    contract: Cow<'a, Hash>,
    // TODO: rework it
    deposits: Option<(&'a IndexMap<Hash, ContractDeposit>, &HashMap<&Hash, DecompressedDepositCt>)>,
    parameters: impl DoubleEndedIterator<Item = ValueCell>,
    gas_sources: IndexMap<Source, u64>,
    max_gas: u64,
    invoke: InvokeContract,
    permission: Cow<'a, InterContractPermission>,
) -> Result<bool, ContractError<E>> {
    debug!("Invoking contract {}: {:?}", contract, invoke);
    // Deposits are actually added to each balance
    let (contract_environment, mut chain_state) = state.get_contract_environment_for(contract.clone(), deposits.map(|(d, _)| d), caller.clone(), permission).await
        .map_err(ContractError::State)?;

    // Total used gas by the VM
    let (used_gas, vm_max_gas, exit_code) = run_virtual_machine(
        contract_environment,
        &mut chain_state,
        invoke,
        contract,
        deposits.map(|(d, _)| d.clone()).unwrap_or_default(),
        parameters,
        max_gas
    ).await?;

    let is_success = exit_code == Some(0);
    // If the contract execution was successful, we need to merge the cache
    let mut outputs = chain_state.outputs;

    let gas_injections = chain_state.injected_gas;
    let modules = chain_state.modules;

    if is_success {
        let mut caches = chain_state.caches;

        let tracker = chain_state.tracker;
        let assets = chain_state.assets;
        let executions = chain_state.scheduled_executions;

        // Some contract have injected gas to users
        if vm_max_gas > max_gas && !gas_injections.is_empty() {
            // Refund only based on the extra max gas
            refund_extra_gas_injections(state, gas_injections, max_gas, vm_max_gas, &mut outputs, &mut caches).await?;
        }

        state.merge_contract_changes(
            caches,
            tracker,
            assets,
            executions,
        ).await
            .map_err(ContractError::State)?;

        if !gas_sources.is_empty() {
            // Refund the whole extra gas injections
            refund_gas_sources(state, gas_sources, used_gas, max_gas).await?;
        }
    } else {
        // Otherwise, something was wrong, we delete the outputs made by the contract
        outputs.clear();

        if !gas_sources.is_empty() {
            refund_gas_sources(state, gas_sources, used_gas, max_gas).await?;
        }

        // But, if we got any gas injection, fully consume it despite the error returned
        // otherwise it allows free invoke attacks
        if used_gas > max_gas && !gas_injections.is_empty() {
            // We consume only what was used above the original max gas
            process_gas_injections(state, gas_injections, used_gas, vm_max_gas, &mut outputs).await?;
        }

        // decompressed deposits may be empty because we only have plaintext deposits
        if let Some((deposits, decompressed_deposits)) = deposits {
            match &caller {
                ContractCaller::Transaction(hash, tx) => {
                    debug!("refunding deposits for transaction {}", hash);
                    refund_deposits(tx.get_source(), state, deposits, decompressed_deposits).await?;
                },
                ContractCaller::Scheduled(_, _) => {
                    warn!("we have some deposits to refund but no TX is linked to it! These deposits are now lost in the void");
                }
            }

            // It was not successful, we need to refund the deposits
            outputs.push(ContractLog::RefundDeposits);
        }
    }

    // Keep modules cache that have been loaded already
    state.set_modules_cache(modules).await
        .map_err(ContractError::State)?;

    let refund_gas = handle_gas(&caller, state, used_gas, max_gas).await?;
    debug!("used gas: {}, refund gas: {}", used_gas, refund_gas);

    if refund_gas > 0 {
        outputs.push(ContractLog::RefundGas { amount: refund_gas });
    }

    // Push the exit code to the outputs
    outputs.push(ContractLog::ExitCode(exit_code));

    // Track the outputs
    state.set_contract_logs(caller, outputs).await
        .map_err(ContractError::State)?;

    Ok(is_success)
}

// We need to refund the extra (unused) gas
// this is the tx max gas - used gas
// We want to refund proportionally to the injections made
pub async fn refund_gas_sources<'a, P: ContractProvider, E, B: BlockchainApplyState<'a, P, E>>(
    state: &mut B,
    gas_sources: IndexMap<Source, u64>,
    used_gas: u64,
    tx_max_gas: u64,
) -> Result<(), ContractError<E>> {
    let mut gas_refund_left = tx_max_gas.checked_sub(used_gas)
        .ok_or(ContractError::GasOverflow)?;

    // Refund proportionally to the injections made
    // examples:
    // available: 1000
    // injected 1: 200
    // injected 2: 200
    // used: 1200
    // refund 1: 100
    // refund 2: 100
    let total_injected: u64 = gas_sources.values().sum();
    if total_injected == 0 {
        return Ok(());
    }

    let initial_gas_refund = gas_refund_left;
    for (source, gas) in gas_sources.into_iter() {
        if gas_refund_left == 0 {
            break;
        }

        // Calculate the proportion of the injection without float
        let proportion = (gas as u128 * initial_gas_refund as u128) / total_injected as u128;
        let refund = proportion as u64;

        let refund_amount = refund.min(gas_refund_left);

        match source {
            Source::Contract(contract) => {
                let (versioned_state, balance) = state.get_contract_balance_for_gas(&contract).await
                    .map_err(ContractError::State)?;

                versioned_state.mark_updated();

                *balance += refund_amount;
                debug!("Refund {} XEL to contract {} for gas fee", refund_amount, contract);
            },
            Source::Account(account) => {
                debug!("Refund {} XEL to account {} for gas fee", refund_amount, account.as_address(state.is_mainnet()));
                let balance = state.get_receiver_balance(Cow::Owned(account), Cow::Owned(XELIS_ASSET)).await
                    .map_err(ContractError::State)?;

                *balance += refund_amount;
            }
        }

        gas_refund_left = gas_refund_left.saturating_sub(refund_amount);
    }

    Ok(())
}

// Refund extra gas injections when the max gas was increased
// in the contract caches
pub async fn refund_extra_gas_injections<'a, P: ContractProvider, E, B: BlockchainApplyState<'a, P, E>>(
    state: &mut B,
    gas_injections: IndexMap<Source, u64>,
    max_gas: u64,
    vm_max_gas: u64,
    outputs: &mut Vec<ContractLog>,
    caches: &mut HashMap<Hash, ContractCache>,
) -> Result<(), ContractError<E>> {
    let mut gas_refund_left = vm_max_gas.checked_sub(max_gas)
        .ok_or(ContractError::GasOverflow)?;

    // Reverse the iterator so the latest entry is the first to be refunded
    for (source, gas) in gas_injections.into_iter().rev() {
        // the gas provided by the contract
        // is lower or equal to whats left to refund
        match source {
            Source::Contract(contract) => {
                if gas_refund_left > 0 {
                    let cache = caches.get_mut(&contract)
                        .ok_or(ContractError::ContractCache)?;

                    let (state, balance) = cache.balances.get_mut(&XELIS_ASSET)
                        .ok_or(ContractError::GasBalance)?
                        .as_mut()
                        .ok_or(ContractError::GasBalance)?;

                    // Refund the smaller of what was injected or what's left
                    let refund = gas.min(gas_refund_left);
                    debug!("Refund {} XEL to contract {} for gas fee", refund, contract);
                    *balance += refund;
                    state.mark_updated();

                    let consumed = gas - refund;

                    debug!("Contract {} injected {}, refunded {}, consumed {}", contract, gas, refund, consumed);

                    // if we have consumed any, track it
                    if consumed > 0 {
                        outputs.push(ContractLog::GasInjection { contract, amount: consumed });
                    }

                    gas_refund_left -= refund;
                } else {
                    // Nothing left to refund, so this contract's full injection was consumed
                    debug!("Contract {} fully consumed {} gas", contract, gas);
                    outputs.push(ContractLog::GasInjection { contract, amount: gas });
                }
            },
            Source::Account(account) => {
                if gas_refund_left > 0 {
                    // Refund to the user account
                    let refund = gas.min(gas_refund_left);
                    debug!("Refund {} XEL to account {} for gas fee", refund, account.as_address(state.is_mainnet()));

                    let balance = state.get_receiver_balance(Cow::Owned(account), Cow::Owned(XELIS_ASSET)).await
                        .map_err(ContractError::State)?;

                    *balance += refund;
                    gas_refund_left -= refund;
                }
            }
        }
    }

    Ok(())
}

// Directly apply to the state the gas injections consumed
pub async fn process_gas_injections<'a, P: ContractProvider, E, B: BlockchainApplyState<'a, P, E>>(
    state: &mut B,
    gas_injections: IndexMap<Source, u64>,
    used_gas: u64,
    max_gas: u64,
    outputs: &mut Vec<ContractLog>,
) -> Result<(), ContractError<E>> {
    // Everything that was spend over the initial max gas
    // we need to consume from the injections
    let mut extra_gas = max_gas.checked_sub(used_gas)
        .ok_or(ContractError::GasOverflow)?;

    // Consume the injections in order
    // so the first to inject is the first to be consumed
    for (source, gas) in gas_injections.into_iter() {
        if extra_gas == 0 {
            break;
        }

        // Consume as much as possible from this contract’s injection
        let consumed = gas.min(extra_gas);

        // Decrease what’s left to cover
        extra_gas -= consumed;

        // Consume the used gas from the source balance
        match source {
            Source::Contract(contract) => {
                debug!("Consume gas injection of {} from contract {} despite error", gas, contract);
                    // Retrieve the balance before execution
                    // we will apply the gas fee on it
                    let (versioned_state, balance) = state.get_contract_balance_for_gas(&contract).await
                        .map_err(ContractError::State)?;

                    versioned_state.mark_updated();

                    *balance = balance
                        .checked_sub(consumed)
                        .ok_or(ContractError::GasOverflow)?;

                outputs.push(ContractLog::GasInjection { contract, amount: consumed });
            },
            Source::Account(account) => {
                // Nothing to do, because it was taken from the gas usage directly
                debug!("Consume gas injection of {} from account {} despite error", gas, account.as_address(state.is_mainnet()));
            }
        }
    }

    Ok(())
}

pub async fn handle_gas<'a, P: ContractProvider, E, B: BlockchainApplyState<'a, P, E>>(
    caller: &ContractCaller<'a>,
    state: &mut B,
    used_gas: u64,
    tx_max_gas: u64,
) -> Result<u64, ContractError<E>> {
    // Part of the gas is burned
    let burned_gas = used_gas * TX_GAS_BURN_PERCENT / 100;
    // Part of the gas is given to the miners as fees
    let gas_fee = used_gas.checked_sub(burned_gas)
        .ok_or(ContractError::GasOverflow)?;
    // The remaining gas is refunded to the sender
    // if used gas is above tx max gas, we don't
    // refund any gas to user
    let refund_gas = if used_gas > tx_max_gas {
        0
    } else {
        tx_max_gas - used_gas
    };

    debug!("Invoke contract used gas: {}, burned: {}, fee: {}, refund: {}", used_gas, burned_gas, gas_fee, refund_gas);
    state.add_burned_fee(burned_gas).await
        .map_err(ContractError::State)?;

    state.add_gas_fee(gas_fee).await
        .map_err(ContractError::State)?;

    if refund_gas > 0 {
        // If we have some funds to refund, we add it to the sender balance
        // But to prevent any front running, we add to the sender balance by considering him as a receiver.
        if let ContractCaller::Transaction(_, tx) = caller {
            let balance = state.get_receiver_balance(Cow::Borrowed(tx.get_source()), Cow::Owned(XELIS_ASSET)).await
                .map_err(ContractError::State)?;

            *balance += Scalar::from(refund_gas);
        }
    }

    Ok(refund_gas)
}

// Refund the deposits made by the user to the contract
pub async fn refund_deposits<'a, P: ContractProvider, E, B: BlockchainApplyState<'a, P, E>>(
    source: &'a CompressedPublicKey,
    state: &mut B,
    deposits: &'a IndexMap<Hash, ContractDeposit>,
    decompressed_deposits: &HashMap<&Hash, DecompressedDepositCt>,
) -> Result<(), ContractError<E>> {
    for (asset, deposit) in deposits.iter() {
        trace!("Refunding deposit {:?} for asset: {} to {}", deposit, asset, source.as_address(state.is_mainnet()));

        let balance = state.get_receiver_balance(Cow::Borrowed(source), Cow::Borrowed(asset)).await
            .map_err(ContractError::State)?;

        match deposit {
            ContractDeposit::Public(amount) => {
                *balance += Scalar::from(*amount);
            },
            ContractDeposit::Private { .. } => {
                let ct = decompressed_deposits.get(asset)
                    .ok_or(ContractError::DepositNotFound)?;

                *balance += Ciphertext::new(ct.commitment.clone(), ct.sender_handle.clone());
            }
        }
    }

    Ok(())
}