use anyhow::Result;
use xelis_common::{
    api::daemon::HardFork,
    block::{Algorithm, BlockVersion},
    network::Network
};
use crate::config::get_hard_forks;

// Get the hard fork at a given height
pub fn get_hard_fork_at_height(network: &Network, height: u64) -> Option<&HardFork> {
    for hardfork in get_hard_forks(network) {
        if height == hardfork.height {
            return Some(hardfork);
        }
    }
    None
}

// Get the version of the hard fork at a given height
// and returns true if there is a hard fork (version change) at that height
pub fn has_hard_fork_at_height(network: &Network, height: u64) -> (bool, BlockVersion) {
    match get_hard_fork_at_height(network, height) {
        Some(hard_fork) => (hard_fork.height == height, hard_fork.version),
        None => (false, BlockVersion::V0)
    }
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

// This function checks if a version is matching the requirements
// it split the version if it contains a `-` and only takes the first part
// to support our git commit hash
fn is_version_matching_requirement(version: &str, req: &str) -> Result<bool> {
    let r = semver::VersionReq::parse(req)?;
    let str_version = match version.split_once('-') {
        Some((v, _)) => v,
        None => version
    };

    let v = semver::Version::parse(str_version)?;

    Ok(r.matches(&v))
}

// This function checks if a version is allowed at a given height
pub fn is_version_allowed_at_height(network: &Network, height: u64, version: &str) -> Result<bool> {
    for hard_fork in get_hard_forks(network) {
        if let Some(req) = hard_fork.version_requirement.filter(|_| hard_fork.height <= height) {
            if !is_version_matching_requirement(version, req)? {
                return Ok(false);
            }
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use xelis_common::config::VERSION;

    use super::*;

    #[test]
    fn test_version_matching_requirement() {
        assert_eq!(is_version_matching_requirement("1.0.0-abcdef", ">=1.0.0").unwrap(), true);
        assert_eq!(is_version_matching_requirement("1.0.0-999", ">=1.0.0").unwrap(), true);
        assert_eq!(is_version_matching_requirement("1.0.0-abcdef999", ">=1.0.0").unwrap(), true);
        assert_eq!(is_version_matching_requirement("1.0.0", ">=1.0.1").unwrap(), false);
        assert_eq!(is_version_matching_requirement("1.0.0", "<1.0.1").unwrap(), true);
        assert_eq!(is_version_matching_requirement("1.0.0", "<1.0.0").unwrap(), false);
    }

    #[test]
    fn test_current_version_against_mainnet_hard_forks() {
        const VERSIONS: [&str; 3] = ["1.0.0", "1.0.0-abcdef", "1.0.0-abcdef999"];

        for version in VERSIONS {
            assert!(is_version_allowed_at_height(&Network::Mainnet, 0, version).unwrap());
        }

        // Should still be valid as we don't have any requirement
        assert!(is_version_allowed_at_height(&Network::Mainnet, 0, "0.0.0").unwrap());

        // Current version should always be valid on previous versions
        assert!(is_version_allowed_at_height(&Network::Mainnet, 0, &VERSION).unwrap());

        // Should be invalid as we require 1.13.0
        for version in VERSIONS {
            println!("Testing version: {}", version);
            assert!(!is_version_allowed_at_height(&Network::Mainnet, 435_000, version).unwrap());
        }

        // Should be valid as we require 1.13.0
        assert!(is_version_allowed_at_height(&Network::Mainnet, 435_000, "1.13.0").unwrap());
        assert!(is_version_allowed_at_height(&Network::Mainnet, 435_000, VERSION).unwrap());
    }

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