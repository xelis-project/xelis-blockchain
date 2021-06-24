use crate::globals::Hash;
use num_bigint::{BigUint, ToBigUint};
use num_traits::{One};

pub fn check_difficulty(hash: &Hash, difficulty: u64) -> bool {
    let big_diff = difficulty_to_big(difficulty);
    let big_hash = hash_to_big(hash);

    big_hash <= big_diff
}

fn difficulty_to_big(difficulty: u64) -> BigUint {
    if difficulty == 0 {
        panic!("Difficulty can never be zero");
    }

    let big_diff = match ToBigUint::to_biguint(&difficulty) {
        Some(v) => v,
        None => panic!("err on diff")
    };
    let one_lsh_256 = BigUint::one() << 256;
    //println!("difficulty: {} | 1 << 256: {} | diff: {} | result: {}", difficulty, one_lsh_256, big_diff, (&one_lsh_256 / &big_diff));
    one_lsh_256 / big_diff
}

fn hash_to_big(hash: &Hash) -> BigUint {
    BigUint::from_bytes_be(hash)
}