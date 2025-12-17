mod mempool_state;
mod chain_state;

pub use mempool_state::MempoolState;
pub use chain_state::{
    ChainState,
    ApplicableChainState,
};

use log::{trace, debug};
use xelis_common::{
    account::VersionedBalance,
    block::{BlockVersion, TopoHeight},
    config::XELIS_ASSET,
    crypto::{Hash, PublicKey},
    transaction::{Reference, Transaction},
    utils::format_xelis
};

use crate::core::storage::Storage;

use super::{
    hard_fork,
    blockchain,
    error::BlockchainError,
    storage::{AccountProvider, BalanceProvider, DagOrderProvider, PrunedTopoheightProvider}
};

// Verify the transaction fee and returns the leftover from fee max
pub async fn verify_fee<P: AccountProvider>(
    provider: &P,
    tx: &Transaction,
    tx_size: usize,
    topoheight: TopoHeight,
    tx_base_fee: u64,
    block_version: BlockVersion
) -> Result<(u64, u64), BlockchainError> {
    let required_fees = blockchain::estimate_required_tx_fees(provider, topoheight, tx, tx_size, tx_base_fee, block_version).await?;

    // Check if we pay enough fee in this TX
    let (fee_paid, refund) = if required_fees > tx.get_fee() {
        // We don't, but maybe our fee max allows it
        if required_fees > tx.get_fee_limit() {
            debug!("Invalid fees: {} required, {} provided", format_xelis(required_fees), format_xelis(tx.get_fee()));
            return Err(BlockchainError::InvalidTxFee(required_fees, tx.get_fee()));
        }

        // Calculate the left over from fee max against required fee
        let refund = tx.get_fee_limit() - required_fees;
        (required_fees, refund)
    } else {
        // We may pay above the required fee
        // so we simply sub it from fee max
        // It should be safe without the checked_sub
        // because `pre_verify` check fee_limit >= fee
        let refund = tx.get_fee_limit()
            .checked_sub(tx.get_fee())
            .ok_or(BlockchainError::InvalidTxFee(required_fees, tx.get_fee()))?;

        (tx.get_fee(), refund)
    };

    Ok((fee_paid, refund))
}

// Check if a miner is in the unstable height of a reference block
async fn is_miner_until_base_height<S: Storage>(storage: &S, miner: &PublicKey, stable_height: u64, reference: &Hash) -> Result<bool, BlockchainError> {
    let mut stack = Vec::new();
    stack.push((reference.clone(), 0));

    while let Some((current_hash, depth)) = stack.pop() {
        let block_height = storage.get_height_for_block_hash(&current_hash).await?;
        if block_height <= stable_height {
            continue;
        }

        let block = storage.get_block_header_by_hash(&current_hash).await?;

        // Check miner
        if *block.get_miner() == *miner {
            debug!("Miner {} found in unstable height at block {}", miner.as_address(storage.is_mainnet()), current_hash);
            return Ok(true);
        }

        // Add parents to stack
        for parent in block.get_tips() {
            stack.push((parent.clone(), depth + 1));
        }
    }

    Ok(false)
}

async fn is_referencing_previous_output<S: Storage>(storage: &S, tx: &Transaction, reference: &Reference, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
    let reference_block_topo = select_best_topoheight_for_reference(storage, reference, topoheight).await?;
    if let Some((topo, _)) = storage.get_output_balance_in_range(tx.get_source(), &XELIS_ASSET, reference.topoheight, topoheight).await? {
        if reference.topoheight <= topo || reference_block_topo <= topo {
            debug!("Transaction is referencing a previous output at topoheight {}", topo);
            return Ok(true);
        }
    }

    Ok(false)
}

// Verify a transaction before adding it to mempool/chain state
// We only verify the reference and the required fees
pub(super) async fn pre_verify_tx<S: Storage>(storage: &S, tx: &Transaction, stable_topoheight: TopoHeight, base_height: u64, topoheight: TopoHeight, block_version: BlockVersion) -> Result<(), BlockchainError> {
    debug!("Pre-verify TX at topoheight {} and stable topoheight {}", topoheight, stable_topoheight);
    if !hard_fork::is_tx_version_allowed_in_block_version(tx.get_version(), block_version) {
        debug!("Invalid version {} in block {}", tx.get_version(), block_version);
        return Err(BlockchainError::InvalidTxVersion);
    }

    let reference = tx.get_reference();
    // Verify that it is not a fake topoheight
    if topoheight < reference.topoheight {
        debug!("Invalid reference: topoheight {} is higher than chain {}", reference.topoheight, topoheight);
        return Err(BlockchainError::InvalidReferenceTopoheight(reference.topoheight, topoheight));
    }

    if block_version >= BlockVersion::V4 {
        let block_height = storage.get_height_for_block_hash(&reference.hash).await?;
        if base_height < block_height
            && !is_referencing_previous_output(storage, tx, &reference, topoheight).await?
            && is_miner_until_base_height(storage, tx.get_source(), base_height, &reference.hash).await?
        {
            // We are in the unstable height, we must ensure that we are not referencing an unstable block
            debug!("Invalid reference: block height {} is higher than stable height {}", block_height, base_height);
            return Err(BlockchainError::InvalidReferenceBlockHeight(block_height, base_height));
        }
    }

    Ok(())
}

async fn select_best_topoheight_for_reference<S: DagOrderProvider + PrunedTopoheightProvider>(storage: &S, reference: &Reference, current_topoheight: TopoHeight) -> Result<TopoHeight, BlockchainError> {
    let pruned_topoheight = storage.get_pruned_topoheight().await?;

    let reference_block_topo = if storage.is_block_topological_ordered(&reference.hash).await? {
        let topo = storage.get_topo_height_for_hash(&reference.hash).await?;
        if topo == reference.topoheight {
            trace!("reference topoheight {} is equal to block topoheight {}", reference.topoheight, topo);
            topo
        } else if reference.topoheight < current_topoheight {
            trace!("reference topoheight {} is lower than current topoheight {}, using current topoheight", reference.topoheight, current_topoheight);
            reference.topoheight
        } else {
            trace!("reference topoheight {} is higher than current topoheight {}, using current topoheight", reference.topoheight, current_topoheight);
            current_topoheight
        }
    } else if pruned_topoheight.filter(|v| *v > reference.topoheight).is_some() {
        trace!("reference topoheight {} is below pruned point, using the reference topoheight", reference.topoheight);
        reference.topoheight
    } else if reference.topoheight < current_topoheight {
        trace!("reference topoheight {} is below current topoheight {}, using reference topoheight", reference.topoheight, current_topoheight);
        reference.topoheight
    } else {
        trace!("using current topoheight {} as reference", current_topoheight);
        current_topoheight
    };

    Ok(reference_block_topo)
}

// Create a sender echange
// This is where the magic happens to fix front running problems
// Returns:
// - If we should use the output balance for verification
// - is it a new version created
// - Versioned Balance to use for verification
pub (super) async fn search_versioned_balance_for_reference<S: DagOrderProvider + BalanceProvider + PrunedTopoheightProvider>(storage: &S, key: &PublicKey, asset: &Hash, current_topoheight: TopoHeight, reference: &Reference, no_new: bool) -> Result<(bool, bool, VersionedBalance), BlockchainError> {
    trace!("search versioned balance for {} at topoheight {}, reference: {}", key.as_address(storage.is_mainnet()), current_topoheight, reference.topoheight);
    // Scenario A
    // TX A has reference topo 1000
    // We are at block topo 1001
    // Because TX A is based on previous block, it is built on final balance

    // Scenario B
    // TX A has reference topo 1000
    // We are at block topo 1005
    // We got some funds in topo 1003
    // We must use the final balance of 1000

    // Scenario C
    // TX A has reference topo 1000
    // We are at block topo 1005
    // We sent another TX B at topo 1001
    // We must use the output balance if available of TX B

    // Scenario D
    // TXs have reference topo 1000
    // We are at block topo 1005
    // We sent another TX B at topo 1003
    // We sent another TX C at topo 1004
    // We must use the output balance if available

    // Retrieve the block topoheight based on reference hash
    let reference_block_topo = select_best_topoheight_for_reference(storage, reference, current_topoheight).await?;

    let mut use_output_balance = false;
    let version;
    // We must verify the last "output" balance for the asset
    // Search the last output balance
    let min_topo = reference.topoheight
        .min(reference_block_topo)
        .min(current_topoheight);

    debug!("Search output balance in range {} to {}", min_topo, current_topoheight);
    let last_output = storage.get_output_balance_in_range(key, asset, min_topo, current_topoheight).await?;
    debug!("output balance found: {}", last_output.is_some());

    // We have a output balance
    if let Some((topo, v)) = last_output {
        trace!("Found output balance at topoheight {}", topo);
        // Verify if the output balance topo is higher than our reference
        if reference.topoheight < topo || reference_block_topo < topo {
            debug!("Scenario C");
            // We must use the output balance if possible because this TX may be built after a previous TX at same reference
            // see Scenario C
            use_output_balance = true;
            version = Some(v);
        } else if topo < reference.topoheight || topo < reference_block_topo {
            trace!("Reference is above last output balance");
            debug!("Scenario B: topo {} < reference {} or reference block topo {}", topo, reference.topoheight, reference_block_topo);

            version = storage.get_balance_at_maximum_topoheight(key, asset, topo.max(reference_block_topo)).await?
                .map(|(topo, v)| {
                    trace!("Found balance at topoheight {}", topo);
                    v
                });
        } else {
            debug!("Scenario A (bis)");
            version = Some(v);
        }
    } else {
        trace!("No output balance found (Scenario B), looking with topo {}", reference_block_topo);
        version = storage.get_balance_at_maximum_topoheight(key, asset, reference_block_topo).await?
            .map(|(topo, v)| {
                trace!("Found balance at topoheight {}", topo);
                v
            });
    }

    let (new_version, version) = if let Some(version) = version {
        trace!("Balance: {}", version);
        (false, version)
    } else {
        // Scenario A
        debug!("Scenario A");
        let (version, new) = storage.get_new_versioned_balance(key, asset, current_topoheight).await?;
        if new && no_new {
            return Err(BlockchainError::NoPreviousBalanceFound);
        }

        (true, version)
    };

    Ok((use_output_balance, new_version,  version))
}