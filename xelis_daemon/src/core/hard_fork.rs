use xelis_common::block::Algorithm;
use crate::config::HARD_FORKS;

// Get the version of the hard fork at a given height
// and returns true if there is a hard fork (version change) at that height
pub fn has_hard_fork_at_height(height: u64) -> (bool, u8) {
    let mut version = 0;
    let mut hard_fork = false;
    for hardfork in HARD_FORKS {
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
pub fn get_version_at_height(height: u64) -> u8 {
    has_hard_fork_at_height(height).1
}

// This function returns the PoW algorithm at a given version
pub fn get_pow_algorithm_for_version(version: u8) -> Algorithm {
    match version {
        0 => Algorithm::V1,
        1 => Algorithm::V2,
        _ => unreachable!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_hard_fork_at_height() {
        let (hard_fork, version) = has_hard_fork_at_height(0);
        assert_eq!(hard_fork, true);
        assert_eq!(version, 0);

        let (hard_fork, version) = has_hard_fork_at_height(1);
        assert_eq!(hard_fork, false);
        assert_eq!(version, 0);
    }

    #[test]
    fn test_get_version_at_height() {
        assert_eq!(get_version_at_height(0), 0);
        assert_eq!(get_version_at_height(100_000), 0);
    }

    #[test]
    fn test_get_pow_algorithm_for_version() {
        assert_eq!(get_pow_algorithm_for_version(0), Algorithm::V1);
    }
}