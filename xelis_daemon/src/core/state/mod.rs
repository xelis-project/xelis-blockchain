mod mempool_state;
mod chain_state;

use log::{trace, debug};
pub use mempool_state::MempoolState;
pub use chain_state::{ChainState, ApplicableChainState, StorageReference};
use xelis_common::{account::VersionedBalance, crypto::{Hash, PublicKey}, transaction::Reference};

use super::{error::BlockchainError, storage::Storage};

// Create a sender echange
// This is where the magic happens to fix front running problems
// Returns:
// - If we should use the output balance for verification
// - is it a new version created
// - Versioned Balance to use for verification
pub (super) async fn search_versioned_balance_for_reference<S: Storage>(storage: &S, key: &PublicKey, asset: &Hash, current_topoheight: u64, reference: &Reference) -> Result<(bool, bool, VersionedBalance), BlockchainError> {
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


    let mut use_output_balance = false;
    let mut version = None;
    // We must verify the last "output" balance for the asset
    // Search the last output balance
    let last_output = storage.get_output_balance_at_maximum_topoheight(key, asset, current_topoheight).await?;
    // We have a output balance
    if let Some((topo, v)) = last_output {
        trace!("Found output balance at topoheight {}", topo);
        // Verify if the output balance topo is higher than our reference
        let mut reference_block_topo = None;
        if reference.topoheight < topo || {
            // Search the topoheight of the reference block in case of reorg
            let t = storage.get_topo_height_for_hash(&reference.hash).await?;
            let under = t < topo;
            reference_block_topo = Some(t);
            under
        } {
            debug!("Scenario C");
            // We must use the output balance if possible because this TX may be built after a previous TX at same reference
            // see Scenario C
            use_output_balance = true;
            version = Some(v);
        } else if topo < reference.topoheight || {
            // Use cache if available
            if let Some(t) = reference_block_topo {
                t < topo
            } else {
                // Search the topoheight of the reference block in case of reorg
                let t = storage.get_topo_height_for_hash(&reference.hash).await?;
                let under = t < topo;
                reference_block_topo = Some(t);
                under
            }
        } {
            trace!("Reference is above last output balance");
            debug!("Scenario B");

            // Retrieve the block topoheight based on reference hash
            let reference_block_topo = if let Some(t) = reference_block_topo {
                t
            } else {
                storage.get_topo_height_for_hash(&reference.hash).await?
            };

            version = storage.get_balance_at_maximum_topoheight(key, asset, reference.topoheight.max(reference_block_topo)).await?
                .map(|(_, v)| v);
        }
    } else {
        trace!("No output balance found");
        // Retrieve the block topoheight based on reference hash
        let reference_block_topo = storage.get_topo_height_for_hash(&reference.hash).await?;

        // There was no reorg, we can use the final balance of the reference block
        if reference_block_topo == reference.topoheight {
            debug!("Scenario B bis (no output balance)");
            // We must use the final balance of the reference block
            // see Scenario B
            version = storage.get_balance_at_maximum_topoheight(key, asset, reference_block_topo).await?
                .map(|(_, v)| v);
        } else {
            debug!("Scenario Luck bis (no output balance)");
            version = storage.get_balance_at_maximum_topoheight(key, asset, reference.topoheight).await?
                .map(|(_, v)| v);
        }
    }

    let (new_version, version) = if let Some(version) = version {
        (false, version)
    } else {
        // Scenario A
        debug!("Scenario A");
        (true, storage.get_new_versioned_balance(key, asset, current_topoheight).await?)
    };

    Ok((use_output_balance, new_version,  version))
}