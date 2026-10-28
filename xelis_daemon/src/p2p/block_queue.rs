use std::{collections::{HashSet, VecDeque}, sync::Arc};
use xelis_common::{block::Block, crypto::Hash};

// Preparation completes in any order. Keep descendants behind their pending
// parents, without holding back unrelated DAG branches. Storage and consensus
// checks still run in the sequential block verifier.
pub(super) struct BlockQueue<T> {
    pending: HashSet<Arc<Hash>>,
    prepared: VecDeque<(Block, Arc<Hash>, T)>,
}

impl<T> BlockQueue<T> {
    pub fn new() -> Self {
        Self {
            pending: HashSet::new(),
            prepared: VecDeque::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn prepared_len(&self) -> usize {
        self.prepared.len()
    }

    pub fn reserve(&mut self, hash: Arc<Hash>) -> bool {
        self.pending.insert(hash)
    }

    // Release on completion, including failed preparation or verification.
    // Children of a failed parent can then reach the normal missing-tip checks.
    pub fn complete(&mut self, hash: &Hash) {
        self.pending.remove(hash);
    }

    pub fn push(&mut self, block: Block, hash: Arc<Hash>, value: T) {
        self.prepared.push_back((block, hash, value));
    }

    pub fn pop_ready(&mut self) -> Option<(Block, Arc<Hash>, T)> {
        let index = self.prepared.iter().position(|(block, _, _)| {
            block.get_tips().iter().all(|tip| !self.pending.contains(tip))
        })?;
        self.prepared.remove(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indexmap::IndexSet;
    use xelis_common::{block::{BlockHeader, BlockVersion, EXTRA_NONCE_SIZE}, crypto::Hashable};
    use crate::config::DEV_PUBLIC_KEY;

    fn block(nonce: u64, tips: &[Hash]) -> (Block, Arc<Hash>) {
        let mut header = BlockHeader::new(BlockVersion::V0, 1, 0, tips.iter().cloned().collect::<IndexSet<_>>(), [0; EXTRA_NONCE_SIZE], DEV_PUBLIC_KEY.clone(), IndexSet::new());
        header.nonce = nonce;
        let hash = Arc::new(header.hash());
        (Block::new(header, Vec::new()), hash)
    }

    #[test]
    fn independent_branch_bypasses_a_pending_parent_and_child() {
        let mut queue = BlockQueue::new();
        let (parent, parent_hash) = block(1, &[]);
        let (child, child_hash) = block(2, &[parent_hash.as_ref().clone()]);
        let (independent, independent_hash) = block(3, &[]);
        assert!(queue.reserve(parent_hash.clone()));
        assert!(queue.reserve(child_hash.clone()));
        assert!(queue.reserve(independent_hash.clone()));

        // The parent is still downloading; the child finished first.
        queue.push(child, child_hash.clone(), ());
        queue.push(independent, independent_hash.clone(), ());
        assert_eq!(queue.pop_ready().unwrap().1, independent_hash);
        assert!(queue.pop_ready().is_none());
        queue.complete(&independent_hash);

        queue.push(parent, parent_hash.clone(), ());
        assert_eq!(queue.pop_ready().unwrap().1, parent_hash);
        // Removing a prepared block is not completion: insertion must finish.
        assert!(queue.pop_ready().is_none());
        queue.complete(&parent_hash);
        assert_eq!(queue.pop_ready().unwrap().1, child_hash);
        queue.complete(&child_hash);
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn all_pending_tips_must_finish_before_a_merge() {
        let mut queue = BlockQueue::new();
        let (_, left) = block(1, &[]);
        let (_, right) = block(2, &[]);
        let (merge, hash) = block(3, &[left.as_ref().clone(), right.as_ref().clone()]);
        queue.reserve(left.clone());
        queue.reserve(right.clone());
        queue.reserve(hash.clone());
        queue.push(merge, hash.clone(), ());
        queue.complete(&left);
        assert!(queue.pop_ready().is_none());
        queue.complete(&right);
        assert_eq!(queue.pop_ready().unwrap().1, hash);
    }

    #[test]
    fn failed_parent_releases_children_for_normal_validation_and_allows_retry() {
        let mut queue = BlockQueue::new();
        let (_, parent_hash) = block(1, &[]);
        let (child, child_hash) = block(2, &[parent_hash.as_ref().clone()]);
        assert!(queue.reserve(parent_hash.clone()));
        assert!(!queue.reserve(parent_hash.clone()));
        queue.reserve(child_hash.clone());
        queue.push(child, child_hash.clone(), ());
        assert!(queue.pop_ready().is_none());
        queue.complete(&parent_hash);
        assert_eq!(queue.pop_ready().unwrap().1, child_hash);
        assert!(queue.reserve(parent_hash));
    }
}
