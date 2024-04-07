use std::borrow::Cow;

use xelis_common::{crypto::{hash, Hash, HASH_SIZE}, serializer::Serializer};

// This builder is used to build a merkle tree from a list of hashes
// It uses a bottom-up approach to build the tree
// The tree is built by taking pairs of hashes and hashing them together
// The resulting hash is then added to the list of hashes
// This process is repeated until there is only one hash left
pub struct MerkleBuilder<'a> {
    hashes: Vec<Cow<'a, Hash>>
}

impl<'a> MerkleBuilder<'a> {
    // Create a new MerkleBuilder
    pub fn new() -> Self {
        MerkleBuilder {
            hashes: Vec::new()
        }
    }

    // Create a new MerkleBuilder with a given capacity
    pub fn with_capacity(capacity: usize) -> Self {
        MerkleBuilder {
            hashes: Vec::with_capacity(capacity)
        }
    }

    // Create a new MerkleBuilder from an iterator of hashes
    pub fn from_iter<I>(iter: I) -> Self
        where I: IntoIterator<Item = &'a Hash>
    {
        MerkleBuilder {
            hashes: iter.into_iter().map(|hash| Cow::Borrowed(hash)).collect()
        }
    }

    // Add a hash to the list of hashes
    pub fn add<E: Into<Cow<'a, Hash>>>(&mut self, element: E) {
        self.hashes.push(element.into());
    }

    // Add an element by hashing and adding it to the list of hashes
    pub fn add_element<S: Serializer>(&mut self, element: &S) {
        self.hashes.push(Cow::Owned(hash(&element.to_bytes())));
    }

    /// Add a byte array to the list of hashes
    pub fn add_bytes(&mut self, bytes: &[u8]) {
        self.hashes.push(Cow::Owned(hash(bytes)));
    }

    // Convert a byte array of HASH_SIZE to a Hash and add it to the list of hashes
    pub fn add_as_hash(&mut self, bytes: [u8; HASH_SIZE]) {
        self.hashes.push(Cow::Owned(Hash::new(bytes)));
    }

    // Build the merkle tree and return the root hash
    pub fn build(&mut self) -> Hash {
        while self.hashes.len() > 1 {
            let mut new_hashes = Vec::new();
            for i in (0..self.hashes.len()).step_by(2) {
                let left = &self.hashes[i];
                let right = if i + 1 < self.hashes.len() {
                    self.hashes[i + 1].as_ref()
                } else {
                    self.hashes[i].as_ref()
                };
                let hash = hash(&[left.as_bytes().as_ref(), right.as_bytes().as_ref()].concat());
                new_hashes.push(Cow::Owned(hash));
            }
            self.hashes = new_hashes;
        }
        debug_assert!(self.hashes.len() == 1);
        self.hashes.remove(0).into_owned()
    }

    // Verify the merkle tree with a given root hash
    pub fn verify(&mut self, root: &Hash) -> bool {
        self.build() == *root
    }
}