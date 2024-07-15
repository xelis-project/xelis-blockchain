use xelis_common::{block::{Algorithm, BlockVersion}, network::Network};
use crate::config::get_hard_forks;

// Get the version of the hard fork at a given height
// and returns true if there is a hard fork (version change) at that height
pub fn has_hard_fork_at_height(network: &Network, height: u64) -> (bool, BlockVersion) {
    let mut version = BlockVersion::V0;
    let mut hard_fork = false;
    for hardfork in get_hard_forks(network) {
        if height >= hardfork.height {
            version = hardfork.version;
        }

        if height == hardfork.height {
            hard_fork = true;
            break;
        }
    }
    (hard_fork, version)
}

// This function returns the block version at a given height
pub fn get_version_at_height(network: &Network, height: u64) -> BlockVersion {
    has_hard_fork_at_height(network, height).1
}

// This function returns the PoW algorithm at a given version
pub fn get_pow_algorithm_for_version(version: BlockVersion) -> Algorithm {
    match version {
        BlockVersion::V0 => Algorithm::V1,
        BlockVersion::V1 => Algorithm::V2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_hard_fork_at_height() {
        let (hard_fork, version) = has_hard_fork_at_height(&Network::Testnet, 0);
        assert_eq!(hard_fork, true);
        assert_eq!(version, BlockVersion::V0);

        let (hard_fork, version) = has_hard_fork_at_height(&Network::Testnet, 1);
        assert_eq!(hard_fork, false);
        assert_eq!(version, BlockVersion::V0);


        let (hard_fork, version) = has_hard_fork_at_height(&Network::Testnet, 5);
        assert_eq!(hard_fork, true);
        assert_eq!(version, BlockVersion::V1);

        let (hard_fork, version) = has_hard_fork_at_height(&Network::Testnet, 6);
        assert_eq!(hard_fork, false);
        assert_eq!(version, BlockVersion::V1);
    }

    #[test]
    fn test_get_version_at_height() {
        assert_eq!(get_version_at_height(&Network::Testnet, 0), BlockVersion::V0);
        assert_eq!(get_version_at_height(&Network::Testnet, 100_000), BlockVersion::V1);
    }

    #[test]
    fn test_get_pow_algorithm_for_version() {
        assert_eq!(get_pow_algorithm_for_version(BlockVersion::V0), Algorithm::V1);
        assert_eq!(get_pow_algorithm_for_version(BlockVersion::V1), Algorithm::V2);
    }
}