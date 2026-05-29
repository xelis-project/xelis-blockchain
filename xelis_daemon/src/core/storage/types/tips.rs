use std::{
    collections::{BTreeSet, HashSet, btree_set::IntoIter},
    cmp::Ordering,
};

use log::debug;
use xelis_common::{crypto::Hash, difficulty::CumulativeDifficulty};

// Represents the tips of the chain or of a block
pub type Tips = HashSet<Hash>;

/// A single chain-tip entry carrying its cumulative difficulty so that
/// `SortedTips` can be kept in sorted order without async DB lookups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TipEntry {
    pub hash: Hash,
    pub cumulative_difficulty: CumulativeDifficulty,
}

impl Ord for TipEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Descending by cumulative difficulty, then descending by hash
        other.cumulative_difficulty.cmp(&self.cumulative_difficulty)
            .then_with(|| other.hash.cmp(&self.hash))
    }
}

impl PartialOrd for TipEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Iterator over `SortedTips` yielding hashes in descending cumulative-difficulty order.
pub struct SortedTipsIter<'a> {
    inner: std::collections::btree_set::Iter<'a, TipEntry>,
}

impl<'a> Iterator for SortedTipsIter<'a> {
    type Item = &'a Hash;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|e| &e.hash)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl ExactSizeIterator for SortedTipsIter<'_> {}

impl Clone for SortedTipsIter<'_> {
    fn clone(&self) -> Self {
        SortedTipsIter { inner: self.inner.clone() }
    }
}

/// Consuming iterator over `SortedTips` yielding hashes in order.
pub struct SortedTipsIntoIter {
    inner: IntoIter<TipEntry>,
}

impl Iterator for SortedTipsIntoIter {
    type Item = Hash;

    fn next(&mut self) -> Option<Hash> {
        self.inner.next().map(|e| e.hash)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl ExactSizeIterator for SortedTipsIntoIter {}

impl IntoIterator for SortedTips {
    type Item = Hash;
    type IntoIter = SortedTipsIntoIter;

    fn into_iter(self) -> SortedTipsIntoIter {
        SortedTipsIntoIter { inner: self.0.into_iter() }
    }
}

/// Chain tips for `ChainCache`, maintained in descending cumulative-difficulty order.
/// Storing cum-diff alongside each hash avoids repeated async DB lookups in
/// `sort_tips` when iterating tips for block-template or validation purposes.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SortedTips(BTreeSet<TipEntry>);

impl SortedTips {
    /// Insert a tip. Returns `true` if the hash was not already present.
    pub fn insert(&mut self, hash: Hash, cumulative_difficulty: CumulativeDifficulty) -> bool {
        self.remove(&hash);
        self.0.insert(TipEntry { hash, cumulative_difficulty })
    }

    /// Remove by hash. O(n), but tip sets are tiny.
    pub fn remove(&mut self, hash: &Hash) -> bool {
        if let Some(entry) = self.0.iter().find(|e| &e.hash == hash).cloned() {
            self.0.remove(&entry)
        } else {
            false
        }
    }

    pub fn truncate(&mut self, max_len: usize) {
        while self.0.len() > max_len {
            if let Some(last) = self.0.pop_last() {
                debug!("Truncated tip {} with cumulative difficulty {}", last.hash, last.cumulative_difficulty);
            }
        }
    }

    pub fn contains(&self, hash: &Hash) -> bool {
        self.0.iter().any(|e| &e.hash == hash)
    }

    /// Iterate hashes in descending cumulative-difficulty order.
    pub fn iter(&self) -> SortedTipsIter<'_> {
        SortedTipsIter { inner: self.0.iter() }
    }

    /// Iterate full entries (hash + cumulative difficulty).
    pub fn entries(&self) -> impl Iterator<Item = &TipEntry> {
        self.0.iter()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn clear(&mut self) {
        self.0.clear()
    }

    /// The best tip (highest cumulative difficulty), if any.
    pub fn best(&self) -> Option<&Hash> {
        self.0.iter().next().map(|e| &e.hash)
    }
}

impl<'a> IntoIterator for &'a SortedTips {
    type Item = &'a Hash;
    type IntoIter = SortedTipsIter<'a>;

    fn into_iter(self) -> SortedTipsIter<'a> {
        self.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sorted_tips() {
        let low_hash = Hash::new([1; 32]);
        let high_hash = Hash::new([2; 32]);
        let mid_hash = Hash::new([3; 32]);

        let mut tips = SortedTips::default();
        tips.insert(low_hash.clone(), CumulativeDifficulty::from(10u64));
        tips.insert(high_hash.clone(), CumulativeDifficulty::from(100u64));
        tips.insert(mid_hash.clone(), CumulativeDifficulty::from(50u64));

        let first = tips.iter().next().expect("sorted tips should not be empty");
        assert_eq!(first, &high_hash, "first tip must be the highest cumulative difficulty");
    }
}