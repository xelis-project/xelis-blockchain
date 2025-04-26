use std::{collections::{HashMap, VecDeque}, fmt::Debug, hash::Hash, mem, sync::Arc};

// A queue that allows for O(1) lookup of elements
// The queue is backed by a VecDeque and a HashSet
// The HashSet is used to check if an element is already in the queue
// The VecDeque is used to keep track of the order of the elements
// This can be shared between threads
pub struct Queue<K: Hash + Eq + Debug, V> {
    keys: HashMap<Arc<K>, V>,
    order: VecDeque<Arc<K>>
}

impl<K: Hash + Eq + Debug, V> Queue<K, V> {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            order: VecDeque::new()
        }
    }

    fn push_internal(&mut self, key: K, value: V) {
        let key = Arc::new(key);
        self.keys.insert(key.clone(), value);
        self.order.push_back(key);
    }

    // Pushes a new element to the back of the queue
    // Returns true if the element was added, false if it already exists
    pub fn push(&mut self, key: K, value: V) -> bool {
        if self.keys.contains_key(&key) {
            return false;
        }

        self.push_internal(key, value);
        true
    }

    // Removes and returns the first element
    pub fn pop(&mut self) -> Option<(K, V)> {
        let key = self.order.pop_front()?;
        let value = self.keys.remove(&key)?;

        let key = Arc::try_unwrap(key).expect("Failed to unwrap Arc");
        Some((key, value))
    }

    // Returns true if key is presents in the queue
    pub fn has(&self, key: &K) -> bool {
        self.keys.contains_key(key)
    }

    fn remove_order_internal(&mut self, key: &K) -> Option<Arc<K>> {
        let index = self.order.iter().position(|k| *k.as_ref() == *key)?;
        self.order.remove(index)
    }

    // Removes and returns the element for the given key
    pub fn remove_entry(&mut self, key: &K) -> Option<(K, V)> {
        let value = self.keys.remove(key)?;
        let key = self.remove_order_internal(key)?;

        let key = Arc::try_unwrap(key).expect("Failed to unwrap Arc");
        Some((key, value))
    }

    // Removes and returns the element for the given key
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let value = self.keys.remove(key)?;
        self.remove_order_internal(key)?;

        Some(value)
    }

    // Gets a reference to the element with the given key
    pub fn get(&self, key: &K) -> Option<&V> {
        self.keys.get(key)
    }

    // Gets a mutable reference to the element with the given key
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.keys.get_mut(key)
    }

    // Returns a reference to the element at the given index
    pub fn get_index(&self, index: usize) -> Option<&K> {
        self.order.get(index).map(|k| &**k)
    }

    // Returns a reference to the first value element
    pub fn peek(&self) -> Option<&V> {
        self.order.front()
            .and_then(|k| self.keys.get(k))
    }

    // Returns a mutable reference to the first value element
    pub fn peek_mut(&mut self) -> Option<&mut V> {
        self.order.front()
            .and_then(|k| self.keys.get_mut(k))
    }

    // Returns a reference to the first key element
    pub fn peek_key(&self) -> Option<&K> {
        self.order.front().map(|k| &**k)
    }

    // Returns current size of the queue
    pub fn len(&self) -> usize {
        self.order.len()
    }

    // Returns true if the queue is empty
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    // Clears the queue
    pub fn clear(&mut self) {
        self.keys.clear();
        self.order.clear();
    }

    // Returns an iterator over the keys in the queue
    // Keys are ordered based on the insertion order
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.order.iter().map(|k| &**k)
    }

    // Returns an iterator over the values in the queue
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.keys.values()
    }

    // Delete from queue and returns deleted elements
    pub fn extract_if<'a, F: 'a + FnMut(&K, &V) -> bool>(&'a mut self, mut f: F) -> impl Iterator<Item = (K, V)> + 'a {
        let mut tmp = HashMap::with_capacity(self.keys.len());
        mem::swap(&mut self.keys, &mut tmp);

        tmp.into_iter().filter_map(move |(k, v)| {
            if f(&k, &v) {
                self.remove_order_internal(&k)?;

                let key = Arc::try_unwrap(k)
                    .expect("Failed to unwrap Arc");
                Some((key, v))
            } else {
                self.keys.insert(k, v);
                None
            }
        })
    }
}