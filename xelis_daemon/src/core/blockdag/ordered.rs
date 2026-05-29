use std::hash::Hash;

use indexmap::IndexSet;
use linked_hash_table::LinkedHashSet;

// A trait for ordered sets, implemented by both IndexSet and LinkedHashSet.
pub trait OrderedSet<T> {
    fn insert(&mut self, item: T) -> bool;
    fn contains(&self, item: &T) -> bool;
    fn len(&self) -> usize;
}

impl<T: Hash + Eq> OrderedSet<T> for IndexSet<T> {
    fn insert(&mut self, item: T) -> bool {
        IndexSet::insert(self, item)
    }

    fn contains(&self, item: &T) -> bool {
        IndexSet::contains(self, item)
    }

    fn len(&self) -> usize {
        IndexSet::len(self)
    }
}

impl<T: Hash + Eq> OrderedSet<T> for LinkedHashSet<T> {
    fn insert(&mut self, item: T) -> bool {
        LinkedHashSet::insert(self, item)
    }

    fn contains(&self, item: &T) -> bool {
        LinkedHashSet::contains(self, item)
    }

    fn len(&self) -> usize {
        LinkedHashSet::len(self)
    }
}