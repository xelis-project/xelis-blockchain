mod mempool_state;
mod chain_state;

pub use mempool_state::MempoolState;
pub use chain_state::{
    ChainState,
    ApplicableChainState,
    StorageReference
};

use log::{trace, debug};
use xelis_common::{
    account::VersionedBalance,
    crypto::{Hash, PublicKey},
    transaction::{Reference, Transaction},
    block::{TopoHeight, BlockVersion},
    utils::format_xelis
};

use super::{
    hard_fork,
    blockchain,
    error::BlockchainError,
    storage::{AccountProvider, BalanceProvider, DagOrderProvider, PrunedTopoheightProvider}
};

// Verify a transaction before adding it to mempool/chain state
// We only verify the reference and the required fees
pub (super) async fn pre_verify_tx<P: AccountProvider + BalanceProvider>(provider: &P, tx: &Transaction, stable_topoheight: TopoHeight, topoheight: TopoHeight, block_version: BlockVersion) -> Result<(), BlockchainError> {
    debug!("Pre-verify TX at topoheight {} and stable topoheight {}", topoheight, stable_topoheight);
    if !hard_fork::is_tx_version_allowed_in_block_version(tx.get_version(), block_version) {
        debug!("Invalid version {} in block {}", tx.get_version(), block_version);
        return Err(BlockchainError::InvalidTxVersion);
    }

    let required_fees = blockchain::estimate_required_tx_fees(provider, topoheight, tx, block_version).await?;
    if required_fees > tx.get_fee() {
        debug!("Invalid fees: {} required, {} provided", format_xelis(required_fees), format_xelis(tx.get_fee()));
        return Err(BlockchainError::InvalidTxFee(required_fees, tx.get_fee()));
    }

    let reference = tx.get_reference();
    // Verify that it is not a fake topoheight
    if topoheight < reference.topoheight {
        debug!("Invalid reference: topoheight {} is higher than chain {}", reference.topoheight, topoheight);
        return Err(BlockchainError::InvalidReferenceTopoheight(reference.topoheight, topoheight));
    }

    Ok(())
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
    let pruned_topoheight = storage.get_pruned_topoheight().await?;

    let reference_block_topo = if storage.is_block_topological_ordered(&reference.hash).await {
        let topo = storage.get_topo_height_for_hash(&reference.hash).await?;
        if topo == reference.topoheight {
            topo
        } else if reference.topoheight < current_topoheight {
            reference.topoheight
        } else {
            current_topoheight
        }
    } else if pruned_topoheight.filter(|v| *v > reference.topoheight).is_some() {
        reference.topoheight
    } else {
        current_topoheight
    };

    let mut use_output_balance = false;
    let version;
    // We must verify the last "output" balance for the asset
    // Search the last output balance
    let min_topo = reference.topoheight
        .min(reference_block_topo)
        .min(current_topoheight);

    debug!("Search output balance in range {} to {}", min_topo, current_topoheight);
    let last_output = storage.get_output_balance_in_range(key, asset, min_topo, current_topoheight).await?;
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
                .map(|(_, v)| v);
        } else {
            debug!("Scenario A (bis)");
            version = Some(v);
        }
    } else {
        trace!("No output balance found (Scenario B)");
        version = storage.get_balance_at_maximum_topoheight(key, asset, reference_block_topo).await?
            .map(|(_, v)| v);
    }

    let (new_version, version) = if let Some(version) = version {
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