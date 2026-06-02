use std::{
    cmp::Ordering,
    collections::{BTreeSet, HashMap, HashSet, btree_set::{self, IntoIter}},
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
    inner: btree_set::Iter<'a, TipEntry>,
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
        SortedTipsIntoIter {
            inner: self.ordered.into_iter(),
        }
    }
}

/// Chain tips for `ChainCache`, maintained in descending cumulative-difficulty order.
/// Storing cum-diff alongside each hash avoids repeated async DB lookups in
/// `sort_tips` when iterating tips for block-template or validation purposes.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SortedTips {
    ordered: BTreeSet<TipEntry>,
    by_hash: HashMap<Hash, CumulativeDifficulty>,
}

impl SortedTips {
    /// Insert a tip. Returns `true` if the hash was not already present.
    pub fn insert(&mut self, hash: Hash, cumulative_difficulty: CumulativeDifficulty) -> Option<CumulativeDifficulty> {
        let prev = self
            .by_hash
            .insert(hash.clone(), cumulative_difficulty.clone());

        if prev.is_none() {
            self.ordered.insert(TipEntry {
                hash,
                cumulative_difficulty,
            });
        }

        prev
    }

    /// Remove by hash using O(1) hash lookup + O(log n) ordered-set removal.
    pub fn remove(&mut self, hash: &Hash) -> bool {
        if let Some(cumulative_difficulty) = self.by_hash.remove(hash) {
            self.ordered.remove(&TipEntry {
                hash: hash.clone(),
                cumulative_difficulty,
            })
        } else {
            false
        }
    }

    pub fn truncate(&mut self, max_len: usize) {
        while self.ordered.len() > max_len {
            if let Some(last) = self.ordered.pop_last() {
                self.by_hash.remove(&last.hash);
                debug!("Truncated tip {} with cumulative difficulty {}", last.hash, last.cumulative_difficulty);
            }
        }
    }

    pub fn contains(&self, hash: &Hash) -> bool {
        self.by_hash.contains_key(hash)
    }

    /// Iterate hashes in descending cumulative-difficulty order.
    pub fn iter(&self) -> SortedTipsIter<'_> {
        SortedTipsIter {
            inner: self.ordered.iter(),
        }
    }

    /// Iterate full entries (hash + cumulative difficulty).
    pub fn entries(&self) -> impl Iterator<Item = &TipEntry> {
        self.ordered.iter()
    }

    pub fn len(&self) -> usize {
        self.ordered.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ordered.is_empty()
    }

    pub fn clear(&mut self) {
        self.ordered.clear();
        self.by_hash.clear();
    }

    /// The best tip (highest cumulative difficulty), if any.
    pub fn best(&self) -> Option<&Hash> {
        self.ordered.iter().next().map(|e| &e.hash)
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
        let dup_hash = Hash::new([4; 32]);

        let mut tips = SortedTips::default();
        tips.insert(low_hash.clone(), CumulativeDifficulty::from(10u64));
        tips.insert(high_hash.clone(), CumulativeDifficulty::from(100u64));
        tips.insert(mid_hash.clone(), CumulativeDifficulty::from(50u64));
        assert!(tips.insert(dup_hash.clone(), CumulativeDifficulty::from(50u64)).is_none());

        assert_eq!(tips.len(), 4, "all unique hashes should be inserted");

        let first = tips.iter().next().expect("sorted tips should not be empty");
        assert_eq!(first, &high_hash, "first tip must be the highest cumulative difficulty");
    }

    #[test]
    fn test_update_existing_tip() {
        let hash = Hash::new([9; 32]);
        let competitor = Hash::new([8; 32]);

        let mut tips = SortedTips::default();
        assert!(tips.insert(hash.clone(), CumulativeDifficulty::from(10u64)).is_none());
        assert!(tips.insert(hash.clone(), CumulativeDifficulty::from(100u64)).is_none());
        tips.insert(competitor.clone(), CumulativeDifficulty::from(50u64));

        assert_eq!(tips.len(), 2, "updating an existing hash must not duplicate it");
        assert!(tips.contains(&hash));
        assert_eq!(tips.best(), Some(&hash), "updated hash must be re-ordered");
    }

    #[test]
    fn test_iter_returns_highest_cumulative_difficulty_first() {
        let h1 = Hash::new([11; 32]);
        let h2 = Hash::new([12; 32]);
        let h3 = Hash::new([13; 32]);

        let mut tips = SortedTips::default();
        tips.insert(h1.clone(), CumulativeDifficulty::from(25u64));
        tips.insert(h2.clone(), CumulativeDifficulty::from(75u64));
        tips.insert(h3.clone(), CumulativeDifficulty::from(50u64));

        let ordered: Vec<Hash> = tips.iter().cloned().collect();
        assert_eq!(ordered, vec![h2, h3, h1], "tips must be yielded from highest to lowest cumulative difficulty");
    }
}