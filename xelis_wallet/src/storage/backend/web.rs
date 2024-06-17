use anyhow::Result;
use log::warn;
use thiserror::Error;
use xelis_common::serializer::{Reader, Serializer, Writer};
use std::{
    collections::{BTreeMap, HashMap},
    ops::Deref,
    sync::{Arc, Mutex}
};

#[cfg(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
use base64::{engine::general_purpose::STANDARD, Engine};

#[cfg(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
const PREFIX_DB_KEY: &'static str = "___xelis_db___";

// TODO: maybe use a Rc ?
type IVec = Vec<u8>;

pub struct Db {
    name: String,
    default: Tree,
    trees: Mutex<HashMap<IVec, Tree>>
}

#[derive(Debug, Error)]
#[error("DB Error")]
pub struct DbError(());

impl DbError {
    fn new() -> Self {
        DbError(())
    }
}

/// Open or create a new memory-backed database.
/// The database is stored in the browser's local storage.
/// If the database already exists, it will be opened.
pub fn open<S: Into<String>>(name: S) -> Result<Db> {
    let name: String = name.into();

    let db = Db::new(name);
    #[cfg(all(
        target_arch = "wasm32",
        target_vendor = "unknown",
        target_os = "unknown"
    ))]
    {
        // Access to the browser local storage
        let window = web_sys::window().ok_or(DbError::new())?;
        let local_storage = window.local_storage()
            .map_err(|_| DbError::new())?
            .ok_or(DbError::new())?;
    
        // Check if the database already exists
        let db_name = format!("{}{}", PREFIX_DB_KEY, db.name());
        let item = local_storage.get_item(db_name.as_str())
            .map_err(|_| DbError::new())?;

        // If the database already exists, populate it
        if let Some(content) = item {
            let decoded = STANDARD.decode(content)
                .map_err(|_| DbError::new())?;
            db.import(&decoded)?;
        }
    }

    Ok(db)
}

impl Db {
    /// Create a new memory-backed database.
    pub fn new(name: String) -> Self {
        Self {
            name,
            default: InnerTree::new("default".into()),
            trees: Mutex::new(HashMap::new())
        }
    }

    /// Import a database from a byte slice.
    pub fn import(&self, bytes: &[u8]) -> Result<()> {
        let mut reader = Reader::new(bytes);
        self.populate(&mut reader)
    }

    /// Returns the name of the database.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Open or create a new memory-backed Tree with its own keyspace,
    /// accessible from the `Db` via the provided identifier.
    pub fn open_tree<V: AsRef<[u8]>>(&self, name: V) -> Result<Tree> {
        let mut trees = self.trees.lock().map_err(|_| DbError::new())?;
        let name_ref = name.as_ref();
        match trees.get(name_ref) {
            Some(tree) => Ok(tree.clone()),
            None => {
                let tree = InnerTree::new(name_ref.into());
                trees.insert(name.as_ref().to_vec(), tree.clone());
                Ok(tree)
            }
        }
    }

    /// Drop a tree from the `Db`, removing its keyspace.
    pub fn drop_tree<V: AsRef<[u8]>>(&self, name: V) -> Result<()> {
        let mut trees = self.trees.lock().map_err(|_| DbError::new())?;
        let name_ref = name.as_ref();
        match trees.remove(name_ref) {
            Some(_) => Ok(()),
            None => {
                warn!("Tree {} does not exist", String::from_utf8_lossy(name_ref));
                Ok(())
            }
        }
    }

    /// Synchronously flushes all dirty IO buffers and calls
    /// fsync. If this succeeds, it is guaranteed that all
    /// previous writes will be recovered if the system
    /// crashes. Returns the number of bytes flushed during
    /// this call.
    pub fn flush(&self) -> Result<usize> {
        let mut writer = Writer::new();
        self.export(&mut writer)?;
        let total = writer.total_write();

        #[cfg(all(
            target_arch = "wasm32",
            target_vendor = "unknown",
            target_os = "unknown"
        ))]
        {
            let window = web_sys::window().ok_or(DbError::new())?;
            let local_storage = window.local_storage()
                .map_err(|_| DbError::new())?
                .ok_or(DbError::new())?;
    
            let encoded = STANDARD.encode(writer.bytes());

            let db_name = format!("{}{}", PREFIX_DB_KEY, self.name());
            local_storage.set_item(db_name.as_str(), encoded.as_str())
                .map_err(|_| DbError::new())?;
        }

        Ok(total)
    }

    /// Asynchronously flushes all dirty IO buffers
    /// and calls fsync. If this succeeds, it is
    /// guaranteed that all previous writes will
    /// be recovered if the system crashes. Returns
    /// the number of bytes flushed during this call.
    pub async fn flush_async(&self) -> Result<usize> {
        self.flush()
    }

    /// Export the database to a writer.
    fn export(&self, writer: &mut Writer) -> Result<()> {
        let trees = self.trees.lock()
            .map_err(|_| DbError::new())?;

        // Write the default tree
        self.default.export(writer)?;

        // Write the trees
        let len = trees.len() as u16;
        writer.write_u16(len);
        for (k, v) in trees.iter() {
            k.write(writer);
            v.export(writer)?;
        }

        Ok(())
    }

    /// Populate the database from a reader.
    fn populate(&self, reader: &mut Reader) -> Result<()> {
        let mut trees = self.trees.lock()
            .map_err(|_| DbError::new())?;

        // Read the default tree
        self.default.populate(reader)?;

        // Read the trees
        let len = reader.read_u16()?;
        for _ in 0..len {
            let k = IVec::read(reader)?;
            let tree = InnerTree::new(k.clone());
            tree.populate(reader)?;
            trees.insert(k, tree);
        }

        Ok(())
    }
}

impl Deref for Db {
    type Target = Tree;

    fn deref(&self) -> &Tree {
        &self.default
    }
}

pub struct InnerTree {
    name: IVec,
    entries: Mutex<BTreeMap<IVec, IVec>>
}

pub type Tree = Arc<InnerTree>;

impl InnerTree {
    /// Create a new `Tree` with the provided name.
    fn new(name: IVec) -> Tree {
        Arc::new(InnerTree {
            name,
            entries: Mutex::new(BTreeMap::new())
        })
    }

    /// Returns the name of the tree.
    pub fn name(&self) -> IVec {
        self.name.clone()
    }

    /// Insert a key to a new value, returning the last value if it
    /// was set.
    pub fn insert<K, V>(&self, key: K, value: V) -> Result<Option<IVec>>
    where
        K: AsRef<[u8]>,
        V: Into<IVec>,
    {
        let mut entries = self.entries.lock().map_err(|_| DbError::new())?;
        let old = entries.insert(key.as_ref().to_vec(), value.into());
        Ok(old)
    }

    /// Retrieve a value from the `Tree` if it exists.
    pub fn get<K: AsRef<[u8]>>(&self, key: K) -> Result<Option<IVec>> {
        let entries = self.entries.lock().map_err(|_| DbError::new())?;
        Ok(entries.get(key.as_ref()).cloned())
    }

    /// Returns `true` if the `Tree` contains a value for
    /// the specified key.
    pub fn contains_key<K: AsRef<[u8]>>(&self, key: K) -> Result<bool> {
        self.get(key).map(|v| v.is_some())
    }

    /// Delete a value, returning the old value if it existed.
    pub fn remove<K: AsRef<[u8]>>(&self, key: K) -> Result<Option<IVec>> {
        let mut entries = self.entries.lock().map_err(|_| DbError::new())?;
        Ok(entries.remove(key.as_ref()))
    }

    /// Returns `true` if the `Tree` contains no elements.
    pub fn is_empty(&self) -> bool {
        let entries = self.entries.lock().expect("Poisoned");
        entries.is_empty()
    }

    /// Returns the number of elements in this tree.
    pub fn len(&self) -> usize {
        let entries = self.entries.lock().expect("Poisoned");
        entries.len()
    }

    /// Clears the `Tree`, removing all values.
    pub fn clear(&self) -> Result<()> {
        let mut entries = self.entries.lock().map_err(|_| DbError::new())?;
        entries.clear();
        Ok(())
    }

    /// Create a double-ended iterator over the tuples of keys and
    /// values in this tree.
    pub fn iter(self: &Tree) -> Iter {
        Iter {
            tree: self.clone(),
            skip: 0
        }
    }

    /// Internal function to export the tree to a writer.
    fn export(&self, writer: &mut Writer) -> Result<()> {
        let entries = self.entries.lock()
            .map_err(|_| DbError::new())?;

        let len = entries.len() as u16;
        writer.write_u16(len);
        for (k, v) in entries.iter() {
            k.write(writer);
            v.write(writer);
        }

        Ok(())
    }

    /// Internal function to populate the tree from a reader.
    fn populate(&self, reader: &mut Reader) -> Result<()> {
        let mut entries = self.entries.lock()
            .map_err(|_| DbError::new())?;

        let len = reader.read_u16()?;
        for _ in 0..len {
            let k = IVec::read(reader)?;
            let v = IVec::read(reader)?;
            entries.insert(k, v);
        }

        Ok(())
    }
}

// TODO: rework this
// A reference to all the entries in a `Tree`.
// So, even if it get changed while we iter, we still have a reference to the old entries.
pub struct Iter {
    tree: Tree,
    skip: usize
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
        let entries = match self.tree.entries.lock() {
            Ok(entries) => entries,
            Err(_) => return Some(Err(DbError::new().into())),
        };

        let skip = self.skip;
        self.skip += 1;
        let (k, v) = entries.iter().skip(skip).next()?;

        Some(Ok((k.clone(), v.clone())))
    }
}

impl DoubleEndedIterator for Iter {
    fn next_back(&mut self) -> Option<Self::Item> {
        let entries = match self.tree.entries.lock() {
            Ok(entries) => entries,
            Err(_) => return Some(Err(DbError::new().into())),
        };

        let skip = self.skip;
        self.skip += 1;
        let (k, v) = entries.iter().rev().skip(skip).next()?;
        Some(Ok((k.clone(), v.clone())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db() {
        let db = open("test").unwrap();
        let tree = db.open_tree("test").unwrap();
        tree.insert("test", "test").unwrap();

        assert_eq!(tree.get("test").unwrap().unwrap(), b"test");
        assert_eq!(tree.remove("test").unwrap().unwrap(), b"test");
        assert!(tree.get("test").unwrap().is_none());
        assert!(tree.is_empty());
        assert_eq!(tree.len(), 0);

        tree.insert("xelis", "silex").unwrap();
        assert_eq!(tree.len(), 1);

        tree.clear().unwrap();
        assert!(tree.is_empty());
        assert_eq!(tree.len(), 0);

        let mut iter = tree.iter();
        assert!(iter.next().is_none());

        tree.insert("a", "b").unwrap();
        let mut iter = tree.iter();
        assert_eq!(iter.next().unwrap().unwrap(), (b"a".to_vec(), b"b".to_vec()));
        assert!(iter.next().is_none());

        tree.insert("b", "c").unwrap();
        let mut iter = tree.iter();
        assert_eq!(iter.next_back().unwrap().unwrap(), (b"b".to_vec(), b"c".to_vec()));
        assert_eq!(iter.next_back().unwrap().unwrap(), (b"a".to_vec(), b"b".to_vec()));
        assert!(iter.next_back().is_none());

        db.flush().unwrap();
    }

    #[test]
    fn test_db_serialization() {
        let db = open("test").unwrap();
        db.insert("hello", "world").unwrap();

        let tree = db.open_tree("test").unwrap();
        tree.insert("test", "test").unwrap();
        tree.insert("xelis", "silex").unwrap();

        let mut writer = Writer::new();
        db.export(&mut writer).unwrap();
        let bytes = writer.bytes();

        let mut reader = Reader::new(&bytes);
        db.populate(&mut reader).unwrap();

        let tree = db.open_tree("test").unwrap();
        assert_eq!(tree.get("test").unwrap().unwrap(), b"test");
        assert_eq!(tree.get("xelis").unwrap().unwrap(), b"silex");

        assert_eq!(db.get("hello").unwrap().unwrap(), b"world");
        db.flush().unwrap();
    }
}