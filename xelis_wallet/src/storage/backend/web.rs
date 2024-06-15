use anyhow::Result;
use std::ops::Deref;

type IVec = Vec<u8>;

pub struct Db {
    inner: Tree
}

pub fn open<S: Into<String>>(path: S) -> Result<Db> {
    Ok(Db {
        inner: Tree {}
    })
}

impl Db {
    /// Open or create a new memory-backed Tree with its own keyspace,
    /// accessible from the `Db` via the provided identifier.
    pub fn open_tree<V: AsRef<[u8]>>(&self, name: V) -> Result<Tree> {
        Ok(Tree {})
    }

    /// Synchronously flushes all dirty IO buffers and calls
    /// fsync. If this succeeds, it is guaranteed that all
    /// previous writes will be recovered if the system
    /// crashes. Returns the number of bytes flushed during
    /// this call.
    pub fn flush(&self) -> Result<usize> {
        Ok(0)
    }

    /// Asynchronously flushes all dirty IO buffers
    /// and calls fsync. If this succeeds, it is
    /// guaranteed that all previous writes will
    /// be recovered if the system crashes. Returns
    /// the number of bytes flushed during this call.
    pub async fn flush_async(&self) -> Result<usize> {
        Ok(0)
    }
}

impl Deref for Db {
    type Target = Tree;

    fn deref(&self) -> &Tree {
        &self.inner
    }
}

pub struct Tree {}

impl Tree {
    /// Returns the name of the tree.
    pub fn name(&self) -> IVec {
        vec![]
    }

    /// Insert a key to a new value, returning the last value if it
    /// was set.
    pub fn insert<K, V>(&self, key: K, value: V) -> Result<Option<IVec>>
    where
        K: AsRef<[u8]>,
        V: Into<IVec>,
    {
        Ok(None)
    }

    /// Retrieve a value from the `Tree` if it exists.
    pub fn get<K: AsRef<[u8]>>(&self, key: K) -> Result<Option<IVec>> {
        Ok(None)
    }

    /// Returns `true` if the `Tree` contains a value for
    /// the specified key.
    pub fn contains_key<K: AsRef<[u8]>>(&self, key: K) -> Result<bool> {
        self.get(key).map(|v| v.is_some())
    }

    /// Delete a value, returning the old value if it existed.
    pub fn remove<K: AsRef<[u8]>>(&self, key: K) -> Result<Option<IVec>> {
        Ok(None)
    }

    /// Returns `true` if the `Tree` contains no elements.
    pub fn is_empty(&self) -> bool {
        true
    }

    /// Returns the number of elements in this tree.
    pub fn len(&self) -> usize {
        0
    }

    /// Clears the `Tree`, removing all values.
    pub fn clear(&self) -> Result<()> {
        Ok(())
    }

    /// Create a double-ended iterator over the tuples of keys and
    /// values in this tree.
    pub fn iter(&self) -> Iter {
        Iter {}
    }
}

pub struct Iter {

}

impl Iter {
    /// Iterate over the keys of this Tree
    pub fn keys(
        self,
    ) -> impl DoubleEndedIterator<Item = Result<IVec>> + Send + Sync {
        self.map(|r| r.map(|(k, _v)| k))
    }

    /// Iterate over the values of this Tree
    pub fn values(
        self,
    ) -> impl DoubleEndedIterator<Item = Result<IVec>> + Send + Sync {
        self.map(|r| r.map(|(_k, v)| v))
    }
}

impl Iterator for Iter {
    type Item = Result<(IVec, IVec)>;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

impl DoubleEndedIterator for Iter {
    fn next_back(&mut self) -> Option<Self::Item> {
        None
    }
}