use xelis_common::block::Algorithm;

// Get the version of the hard fork at a given height
// and returns true if there is a hard fork (version change) at that height
pub fn has_hard_fork_at_height(_height: u64) -> (bool, u8) {
    (false, 0)
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